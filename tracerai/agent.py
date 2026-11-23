"""TracerAI agent.

    python -m tracerai.agent
"""

import os

import boto3

from strands import Agent, tool
from strands.models import BedrockModel

from rich.console import Console
from rich.markdown import Markdown

from tracerai.tools.reachability import reachability
from tracerai.tools.instances import resolve_instance as _resolve_instance
from tracerai.tools.instances import list_instances as _list_instances
from tracerai.tools.security_groups import describe_security_group as _describe_security_group
from tracerai.tools.security_groups import scan_port as _scan_port
from tracerai.tools.cross_account import discover_network as _discover_network
from tracerai.tools.cross_account import get_vpc_route_tables as _get_vpc_route_tables
from tracerai.tools.cross_account import get_instance_security_groups as _get_instance_security_groups
from tracerai.tools.cross_account import validate_cloud_wan_path as _validate_cloud_wan_path
from tracerai.tools.cross_account import resolve_account as _resolve_account
from tracerai.tools.cross_account import _account_names
from tracerai.tools.reachability_trace import resolve_endpoint as _resolve_endpoint
from tracerai.tools.reachability_trace import trace_cross_account as _trace_cross_account
from tracerai.tools.directconnect import check_direct_connect as _check_direct_connect
from tracerai.tools.directconnect import recommend_dx_resilience as _recommend_dx_resilience
from tracerai.tools.flow_logs import check_vpc_flow_logs as _check_vpc_flow_logs
from tracerai.tools.firewall import check_firewall_rules as _check_firewall_rules
from tracerai.banner import print_banner

console = Console()


class ToolTraceHandler:
    """Strands callback handler that shows tool calls but not the raw text stream.

    The default handler streamed both the model text (raw markdown) and the
    "Tool #N" lines. We render the final answer with rich instead, so this
    handler keeps only the tool-call trace and drops the text and reasoning so
    nothing prints twice.
    """

    def __init__(self):
        self.tool_count = 0

    def __call__(self, **kwargs):
        tool_use = (kwargs.get("event", {}).get("contentBlockStart", {})
                    .get("start", {}).get("toolUse"))
        if tool_use and tool_use.get("name"):
            self.tool_count += 1
            console.print(f"[dim]Tool #{self.tool_count}: {tool_use['name']}[/dim]")


@tool
def resolve_instance(name: str, region: str = None) -> dict:
    """Resolve an EC2 instance by its Name tag to an instance id.

    Call this when the user refers to an instance by name rather than an
    i-xxxx id. Matching is case insensitive and partial, and several regions
    are searched when none is given. Returns `matches` (each with its region)
    and `resolved_id` (set only when there is exactly one running match). When
    there are multiple matches, ask the user which one. When there are no
    matches, the result includes `suggestions` (the instances that were found);
    offer the closest one and ask if that is the one. Note the region of the
    chosen instance and pass it to the other tools.

    Args:
        name: a full or partial Name tag, or a raw instance id.
        region: optional region to narrow the search.
    """
    return _resolve_instance(name, region)


@tool
def resolve_account(name_or_id: str) -> dict:
    """Resolve an AWS account NAME to its 12-digit id so the user never types the number.

    Call this whenever the user refers to an account by name (for example "SpokeDev1",
    "the networking account", "shared services") instead of a 12-digit id. It looks the name
    up in AWS Organizations and matches case insensitively: an exact name wins, otherwise any
    account whose name contains the text. A 12-digit id is validated and named.

    Do NOT ask the user for the 12-digit account id before trying this. After it resolves,
    confirm with the user using the masked id (for example "That is your SpokeDev1 account
    (...9670), correct?"), then pass the full account_id to the other tools.

    Args:
        name_or_id: an account name, a partial name, or a 12-digit account id.

    Returns matches (each with account_id, name, masked), resolved (true when exactly one
    match), and a note when Organizations cannot be read (only then ask for the 12-digit id).
    """
    return _resolve_account(name_or_id)


@tool
def check_reachability(src_id: str, dst_id: str, port: int, region: str = None) -> dict:
    """Check whether one EC2 instance can reach another over TCP on a port.

    Use this ONLY when both instances are in the SAME account (it runs EC2
    Reachability Analyzer, which cannot see another account's route tables). When
    the source and destination are in different accounts, use trace_cross_account
    instead. Requires raw instance ids. Call resolve_instance first for any
    friendly names, and pass the region it reported. Both instances must be in the
    same region.

    Args:
        src_id: source instance id, e.g. "i-0abc..."
        dst_id: destination instance id, e.g. "i-0def..."
        port: destination TCP port, e.g. 3306 (MySQL), 22 (SSH)
        region: the region both instances live in.

    Returns `reachable`, `reason_codes`, and `path_summary`.
    """
    return reachability(src_id, dst_id, port, region=region)


@tool
def check_security_group(target: str, port: int = None, protocol: str = "tcp", region: str = None) -> dict:
    """Inspect the security group rules for an instance or a security group.

    Use this to answer questions like "is security group X allowing port 1010?"
    or "what can reach this instance on 443?", and to explain WHY a reachability
    check was blocked by a security group. Pass the region from resolve_instance
    so the lookup targets the right place.

    Args:
        target: an instance id (i-...) or a security group id (sg-...).
        port: optional port to check for inbound access, e.g. 1010.
        protocol: "tcp" (default) or "udp", used with port.
        region: the region the resource lives in.

    Returns the inbound and outbound rules, plus a port_check verdict when a
    port is given.
    """
    return _describe_security_group(target, port, protocol, region=region)


@tool
def list_instances(region: str = None) -> dict:
    """List all EC2 instances in a region (paginated).

    Use this when the user asks to list or show their instances. If the user
    does not give a region, ask which region first; do not guess. The result
    sets needs_region when no region was provided.

    Args:
        region: the AWS region to list instances in, e.g. "eu-west-1".

    Returns the region, a count, and the instances (id, name, state, type,
    private_ip, az).
    """
    return _list_instances(region)


@tool
def scan_open_port(port: int, protocol: str = "tcp", region: str = None) -> dict:
    """Scan every security group in a region for an open inbound port.

    Use this when the user asks whether a port is open anywhere, for example
    "is port 22 open in any security group in eu-west-1?". It checks all
    security groups in the region, not one instance. If the user does not give
    a region, ask which region first; do not guess.

    Args:
        port: the inbound port to look for, e.g. 22.
        protocol: "tcp" (default) or "udp".
        region: the region to scan, e.g. "eu-west-1".

    Returns open (true/false) and, for each match, the group id, group name,
    and the source CIDRs the port is open to.
    """
    return _scan_port(port, protocol, region=region)


@tool
def discover_network(region: str = None) -> dict:
    """Map the whole network in a region, across accounts.

    Use this when the user asks to discover or map their network. Run from the
    account that owns the Transit Gateway and/or Cloud WAN core network. It
    covers BOTH backbones:
      - Transit Gateway: lists the TGW attachments, then for each connected VPC
        reads that VPC's full detail (CIDRs, subnets, route tables, security
        groups, NACLs, NAT gateways, flow logs) in its owner account.
      - Cloud WAN: lists core networks, their segments and (for this region's
        edge) the segment route tables, then reads each attached VPC's full
        detail in its owner account, plus each attachment's options (appliance
        mode, DNS, IPv6) and subnets.
    It assumes the read-only role for VPCs in other accounts and uses local
    creds for this account's own VPCs (shared, endpoints, centralized). Non-VPC
    attachments (VPN, peering, Direct Connect, TGW-to-Cloud-WAN) are listed
    separately. Each TGW and Cloud WAN VPC attachment also reports its 1:1 NAT
    config (whether NAT is enabled and, for TGW, the rules mapping
    match_source_cidr to nat_cidr). If the user did not give a region, ask first.

    For a cross-region design, pass several regions comma separated, for example
    "eu-west-1,us-east-1"; the result then has by_region keyed by each region.

    Args:
        region: one region (e.g. "eu-west-1"), or several comma separated.

    Returns, for one region: transit_gateways, vpc_attachments, other_attachments
    and cloud_wan. For several: by_region keyed by region. An account missing the
    read-only role is listed with a note, not failed.
    """
    return _discover_network(region)


@tool
def get_vpc_route_tables(vpc_id: str, account_id: str = None, region: str = None) -> dict:
    """Read the route tables for a VPC, in this or another account.

    Use this to answer questions like "what route table is in vpc-abc in account
    123456789012?". When account_id is given, TracerAI assumes a read-only role
    in that account to read it; when omitted, it uses the current account. Ask
    for the region if the user did not give one.

    Args:
        vpc_id: the VPC id, e.g. "vpc-0abc...".
        account_id: the 12-digit account that owns the VPC (optional).
        region: the region the VPC is in.

    Returns the VPC's route tables with their routes, or a note if the account's
    role could not be assumed.
    """
    return _get_vpc_route_tables(vpc_id, account_id=account_id, region=region)


@tool
def get_instance_security_groups(instance_id: str, account_id: str = None, region: str = None) -> dict:
    """Read an instance's security group rules, in this or another account.

    Use this when the user gives an instance id and an account and asks about its
    security groups (for example "check the security group rules on i-abc in
    account 123456789012"). When account_id is given, TracerAI assumes the
    read-only role in that account. Ask for the region if the user did not give
    one.

    Args:
        instance_id: the instance id, e.g. "i-0abc...".
        account_id: the 12-digit account that owns the instance (optional).
        region: the region the instance is in.

    Returns the instance's security groups with inbound and outbound rules, or a
    note if the account's role could not be assumed.
    """
    return _get_instance_security_groups(instance_id, account_id=account_id, region=region)


@tool
def validate_cloud_wan_path(dst_ip: str, return_ip: str = None, segment_name: str = None,
                            core_network_id: str = None, region: str = None) -> dict:
    """Validate how a Cloud WAN segment routes an address, at EVERY edge the segment spans.

    Use this whenever traffic crosses a Cloud WAN core network and you need to know the
    segment actually carries it to the right next hop, both ways. This is the check a
    per-region route read misses: it resolves the destination prefix (and, when given, the
    return/source prefix) inside the segment at each edge location the segment spans, so a
    cross-region Cloud WAN (eu-west-1 plus ca-central-1 plus any you add later) is validated
    in one call with no per-region work. It flags the common faults: a spoke prefix that
    resolves to the inspection or egress attachment instead of its VPC or the TGW peering (a
    prod-to-prod-via-inspection leak), a blackhole, a missing route, and forward/return
    asymmetry. Pass return_ip to validate the return path at the same time, which is usually
    what you want for "why does the ping fail" questions.

    Call this after trace_cross_account reports a "cloud wan segment routing" finding you want
    to expand, or directly when the user points at a Cloud WAN segment. If there is more than
    one core network, pass core_network_id (the error lists them).

    Args:
        dst_ip: the destination address (forward path) to resolve in the segment.
        return_ip: the source address (return path) to resolve too; strongly recommended.
        segment_name: the segment to inspect (e.g. "prod"); omit to check every segment and
            report only the ones that actually carry one of the addresses.
        core_network_id: the core network id; omit when there is only one.
        region: any region the core network touches, used to find the global network; the
            validation itself spans all edges, not just this region.

    Returns per-segment, per-edge results with the matched route, the next-hop classification
    (vpc | peering | inspection | blackhole | none), consistent true/false with a reason, and
    a top-level problems list naming each inconsistent segment/edge.
    """
    return _validate_cloud_wan_path(dst_ip=dst_ip, return_ip=return_ip, segment_name=segment_name,
                                    core_network_id=core_network_id, region=region)


@tool
def resolve_endpoint(identifier: str, account_id: str = None, region: str = None) -> dict:
    """Resolve an endpoint to its instances and network context, in this or another account.

    Use this for CROSS-ACCOUNT reachability, before trace_cross_account: run it for the source and
    again for the destination to turn whatever the user has (a Name tag, an instance id, a private
    IP, or an instance ARN) into a concrete instance with its id, private IP, VPC and subnet. When
    there are several matches, show them and ask the user which one. When account_id is given, the
    read-only role is assumed in that account; a region is required.

    Args:
        identifier: a Name tag (partial, case insensitive), an instance id, a private IP, or an ARN.
        account_id: the 12-digit account that owns the endpoint (optional; omit for this account).
        region: the region to search.

    Returns match_count and candidates (each with instance_id, name, private_ip, vpc_id, subnet_id),
    or an error note if the account's role could not be assumed.
    """
    return _resolve_endpoint(identifier, account_id=account_id, region=region)


@tool
def trace_cross_account(src_instance_id: str, dst: str, port: int, protocol: str = "tcp",
                        region: str = None, src_account_id: str = None,
                        dst_account_id: str = None, tgw_account_id: str = None,
                        src_region: str = None, dst_region: str = None) -> dict:
    """Trace connectivity between two instances in DIFFERENT accounts (read only, config based).

    Use this instead of check_reachability whenever the source and destination are in different AWS
    accounts: EC2 Reachability Analyzer cannot see another account's route tables, so it cannot
    answer cross-account questions. First resolve and confirm BOTH endpoints with resolve_endpoint,
    and ask the user for the port and protocol if they did not give them. Pass raw instance ids and
    the account each one is in. For a cross-region path, set src_region and dst_region.

    It walks the path and reports the first layer that blocks it: source security group egress and
    subnet NACL egress, the source VPC route table, the Transit Gateway route table in the hub
    account, destination security group and NACL ingress, and the return path. It is 1:1 NAT aware:
    if an endpoint's attachment translates its address, the walk uses the translated (outside)
    address, since the source must target the destination's NAT address and the destination sees the
    source's NAT address. For TGW it reads the exact rule; for Cloud WAN the rule CIDRs are not in
    the API, so it reports that and points to the segment route tables. It does not follow the
    inter-region peering or TGW-to-Cloud-WAN hop itself, and flags that as a leg to confirm.

    Args:
        src_instance_id: the source instance id (resolve it first).
        dst: the destination instance id (preferred, so its inbound rules are checked) or a private IP.
        port: the destination TCP/UDP port, e.g. 443. For ICMP it is ignored (pass -1).
        protocol: "tcp" (default), "udp", or "icmp". For ICMP it confirms a rule allows ICMP from
            the source, including an all-traffic (protocol -1) security group rule.
        region: the region both ends are in (single-region shortcut).
        src_region: the source region (for a cross-region trace; defaults to region).
        dst_region: the destination region (for a cross-region trace; defaults to region).
        src_account_id: the account that owns the source.
        dst_account_id: the account that owns the destination.
        tgw_account_id: the Transit Gateway owner (hub) account; when omitted it is resolved from the TGW's OwnerId.

    Returns findings (each step with pass/fail/unknown/info and detail), effective_src/effective_dst
    (the NAT-translated addresses used), and a verdict. Layers it cannot read are unknown, not failed.
    """
    return _trace_cross_account(
        src_instance_id=src_instance_id, dst=dst, port=port, protocol=protocol, region=region,
        src_account_id=src_account_id, dst_account_id=dst_account_id, tgw_account_id=tgw_account_id,
        src_region=src_region, dst_region=dst_region)


@tool
def check_direct_connect(connection_id: str = None, region: str = None,
                         account_id: str = None) -> dict:
    """Check Direct Connect health: connections, virtual interfaces, and BGP peers.

    Use this when the user asks about Direct Connect, a DX connection, a virtual interface (VIF),
    or BGP status over Direct Connect. It reports each connection (dedicated or hosted) and its
    state and location, each VIF and its state, and each BGP peer with bgp_status up or down and
    its address family, plus the prefixes the DX gateway advertises toward on-premises. Pass
    connection_id to scope to one connection, and account_id/region for the account and region the
    Direct Connect lives in (usually the networking account). For resilience or SLA questions use
    recommend_dx_resilience instead.

    Note the API does not return routes RECEIVED from on-premises; for those, read the attached VGW
    or Transit Gateway route table with discover_network or get_vpc_route_tables.

    Args:
        connection_id: a DX connection id (dxcon-...) to scope to, or omit for all.
        region: the region the Direct Connect is in.
        account_id: the account that owns the Direct Connect (optional).

    Returns connections, virtual_interfaces (with bgp_peers), dx_gateways (advertised_prefixes),
    issues, and healthy.
    """
    return _check_direct_connect(connection_id=connection_id, region=region, account_id=account_id)


@tool
def recommend_dx_resilience(region: str = None, account_id: str = None) -> dict:
    """Assess Direct Connect resilience and recommend how to reach 99.9% or 99.99% SLA.

    Use this when the user asks whether their Direct Connect is resilient, or how to reach an SLA.
    It reads the current connections and classifies the posture against the AWS Direct Connect
    Resiliency Toolkit: High Resiliency (99.9%) needs two connections in two different DX locations;
    Maximum Resiliency (99.99%) needs separate connections on distinct devices in more than one
    location. When a location must be added, it suggests DX locations not already in use. Present
    the verdict plainly, for example: "For 99.9% add a connection in a different DX location; for
    99.99% diversify to two locations with redundant connections on distinct devices." Cite the
    returned reference. Use check_direct_connect for health, not this.

    Args:
        region: the region the Direct Connect is in.
        account_id: the account that owns the Direct Connect (optional).

    Returns current (the posture, with meets_99_9 and meets_99_99), recommendations keyed by SLA,
    suggested_additional_locations, and reference.
    """
    return _recommend_dx_resilience(region=region, account_id=account_id)


@tool
def check_vpc_flow_logs(target: str, region: str = None, account_id: str = None,
                        action: str = "REJECT", minutes: int = 60, port: int = None) -> dict:
    """Read VPC flow log records for an interface to see ACCEPT or REJECT traffic.

    Use this for evidence of whether traffic actually reached an interface and was accepted or
    rejected, next to the config the other tools read (for example after a trace says a security
    group should block something, confirm it with REJECT records). This reads VPC flow logs (not
    Cloud WAN flow logs) and only when they are delivered to CloudWatch Logs; if they go to S3 it
    says so. It resolves target to its ENI(s) and queries CloudWatch Logs Insights.

    Args:
        target: an instance id, an ENI id, or a private IP.
        region: the region the interface is in.
        account_id: the account that owns it (optional; uses the read-only role).
        action: "REJECT" (default), "ACCEPT", or "ALL".
        minutes: how far back to look (default 60).
        port: optional destination port to filter (for example 443).

    Returns the matched records (timestamp, src/dst, port, protocol, action), match_count, the
    log group and traffic_type, and notes (for example if the flow log captures ACCEPT only, or
    is not delivered to CloudWatch Logs).
    """
    return _check_vpc_flow_logs(target=target, region=region, account_id=account_id,
                                action=action, minutes=minutes, port=port)


@tool
def check_firewall_rules(src_ip: str, dst_ip: str, port: int, protocol: str = "tcp",
                         region: str = None, account_id: str = None,
                         firewall_name: str = None, firewall_arn: str = None) -> dict:
    """Check whether an AWS Network Firewall allows a flow (the inspection step a trace defers).

    Use this when traffic goes through an inspection VPC / AWS Network Firewall and the user asks
    whether the firewall allows a flow, or when a trace flagged an inspection VPC and you need to
    confirm the firewall side. Give the source and destination IPs (use the NAT-translated address
    if the path is NAT'd), the port and protocol, and the region and account the firewall is in.

    It reads the firewall policy and rule groups and reports a verdict (allowed / blocked), naming
    the rule and action. It evaluates stateless rules, structured stateful rules and the default
    actions precisely; for raw Suricata rule strings it matches the rule header only and says so;
    domain allow/deny lists are named, not matched to an IP. If several firewalls exist it returns
    the list so you can pass firewall_name.

    Args:
        src_ip: source IP of the flow (the address as it reaches the firewall).
        dst_ip: destination IP.
        port: destination port.
        protocol: "tcp" (default), "udp", or "icmp".
        region: the region the firewall is in.
        account_id: the account that owns the firewall (optional).
        firewall_name: the firewall to use when there is more than one.
        firewall_arn: the firewall arn, as an alternative to the name.

    Returns verdict, matched (the rule and action), rule_order, the stateless/stateful defaults,
    and notes for anything not fully evaluable (Suricata options, domain lists).
    """
    return _check_firewall_rules(src_ip=src_ip, dst_ip=dst_ip, port=port, protocol=protocol,
                                 region=region, account_id=account_id,
                                 firewall_name=firewall_name, firewall_arn=firewall_arn)


SYSTEM_PROMPT = """You are TracerAI, an AWS network troubleshooting assistant.
You're expert in AWS Networking, with in depth knowledge in AWS VPC, Cloud WAN, Transit Gateway,
Direct Connect, VPN, Interconnect, SDWAN,
AWS Firewall, DNS, Route 53, Global Accelerator, Gateway Load Balancer, NAT. You use AWS
documentation to understand architectures and use AWS best practices guides to give guidance on how the network
should be improved or built. You also have in depth knowledge in BGP, MPLS, TCP/IP, HTTP and DNS

When the user asks whether resources can connect:
First decide which account each end is in. If BOTH ends are in the same account,
use check_reachability (EC2 Reachability Analyzer). If the ends are in DIFFERENT
accounts (for example "can prod-instance in SpokeDev1 reach shared-services in the
networking account"), Reachability Analyzer cannot see the other account's route
tables, so use the cross-account flow below instead. If you are unsure which
applies, ask whether the two resources are in the same account.

Account names, never ask for the 12-digit id:
When the user names an account instead of giving a 12-digit id (for example
"SpokeDev1", "the networking account", "shared services"), do NOT ask them for
the number. Call resolve_account with the name first.
- If it resolves to exactly one account, confirm with the masked id before you
  use it, for example "That is your SpokeDev1 account (...9670), correct?", then
  pass the full account_id to the other tools.
- If several accounts match, list them by name and masked id and ask which one.
- Only ask the user to type the 12-digit id when resolve_account returns a note
  that Organizations could not be read. A 12-digit id the user gives can also be
  passed through resolve_account to attach its name.
Do the same for every account in the request: resolve and confirm the source
account and the destination account before calling resolve_endpoint or
trace_cross_account.

Same account:
1. If they named an instance by a friendly name (not an i-xxxx id), call
   resolve_instance to get its id, for both source and destination.
   If there are multiple matches, ask the user which one. If none, say so.
2. Once you have both ids, call check_reachability with the port
   (infer common ports from service names: SSH=22, MySQL=3306, HTTPS=443).
3. Explain the result in plain English: whether it is reachable, and if
   blocked, translate reason_codes into human terms (for example
   ENI_SG_RULES_MISMATCH means a security group does not allow that port).
   When a security group is the likely cause, call check_security_group on the
   destination to find the exact rule, then suggest the specific fix.

Cross-account (source and destination in different accounts):
1. Resolve each end with resolve_endpoint, passing whatever the user gave you (a
   name, instance id, private IP, or ARN), the account it is in, and the region.
   If there are several matches, show them and ask the user to confirm the right
   instance by name or id before going on. Do this for the source and the
   destination.
2. Ask for the protocol and port if the user did not give them (infer common
   ports from service names when it is obvious: HTTPS=443, MySQL=3306, SSH=22).
3. Call trace_cross_account with the confirmed source and destination instance
   ids, their accounts, the region, and the port and protocol. The Transit
   Gateway owner (hub) account defaults to the destination account; pass
   tgw_account_id if the hub is a different account.
4. Read the findings in order and explain them plainly. Name the first step with
   result "fail" as the blocker and give the specific fix (for example "add an
   inbound rule on the destination security group allowing tcp/443 from the
   source's IP or CIDR"). Report "unknown" steps as coverage gaps, not failures
   (often a missing or mismatched TRACERAI_EXTERNAL_ID). If there is an
   "inspection / firewall" info finding, tell the user everything around the
   firewall checks out and they should verify the firewall policy allows the
   flow; do not claim the firewall is the problem, only that it was not inspected.

You can also answer direct security group questions (for example "is sg-123
allowing port 1010?") by calling check_security_group with a port.

Scanning for an open port across a region:
- When the user asks whether a port is open anywhere (for example "is port 22
  open in any security group in eu-west-1?"), call scan_open_port, not
  check_security_group. check_security_group is for one instance or one sg;
  scan_open_port checks every security group in the region.
- If no region is given, ask which region first; do not guess.
- Answer plainly: if open is false, say "No, port N is not open in any security
  group in <region>." If open is true, name each group id and the source it is
  open to, for example "Yes, sg-abc has port 22 open to 0.0.0.0/0." Call out a
  0.0.0.0/0 source as open to the whole internet.

Listing instances:
- When the user asks to list or show instances, call list_instances. If they did
  not give a region, ask which region first; do not guess.
- After listing, ask: "Do you want to test connectivity between any of these
  instances?"

When to use check_security_group:
- Any time check_reachability comes back not reachable with a security group
  cause (for example ENI_SG_RULES_MISMATCH), call check_security_group on the
  destination for the tested port before you answer. Do not just say "it is
  probably the security group" without checking.
- Any time the user asks about ports, allowed sources, or inbound or outbound
  rules (for example "is port 1010 open?", "what can reach this on 443?").
- Any time the user suspects the security group, even if they did not ask for a
  reachability check.
- Do not call it when the connection already succeeded.
When a port is blocked, state the rule to add: protocol, port, and the source
CIDR that would allow it.

Network discovery:
- When the user asks to discover or map their network, call discover_network. If
  they did not give a region, ask which region first; do not guess.
- It maps across accounts and across BOTH backbones. Transit Gateway: the TGW and
  its attachments. Cloud WAN: the cloud_wan block, with core networks, their
  segments, segment route tables for the region's edge, and VPC attachments. For
  each connected VPC it reads CIDRs, subnets, route tables, security groups and
  NACLs in the VPC's owner account.

Keep the first discovery answer short: a few sentences of prose, not a data
dump. Lead with the shape of the network and hold the details behind offers. Do
not print wide tables or raw route entries in the first answer. Refer to each
account by its name and masked id from account_name, for example "your SpokeDev1
account (...9670)"; if account_name is null, use the id alone.

The first answer covers only this, briefly:
1. Topology in one line: name the pattern, for example "You have a hub-and-spoke
   setup" (Transit Gateway hub, a segmented Cloud WAN backbone, centralized
   egress or inspection).
2. Attachments in one or two sentences, grouped, with counts, never a table. For
   example: "The Transit Gateway has 8 attachments: 3 VPCs in your Networking
   account (endpoints, shared, prod-inspection), 3 VPCs in SpokeDev1 (...9670),
   plus a Cloud WAN peering, a VPN, and a Direct Connect gateway." Name the hub
   VPCs; group spoke VPCs by account with a count rather than listing raw ids.
3. Cloud WAN in one sentence: the core network, how many regions it spans and
   which, and the segment names. For example: "You also peer with a Cloud WAN
   core network across eu-west-1, ca-central-1 and us-east-1, with segments prod,
   nonprod, endpoints, shared, overlap and hybrid."
4. The shape of the VPCs in aggregate, not a per-VPC wall of text. For example:
   "Each VPC has 2 to 4 subnets, and each subnet uses one route table with about
   3 routes."
5. Then stop and offer; do not dump:
   - "Want me to show the route tables for a particular VPC?" Show route entries
     only after the user asks, and only for the VPC they name.
   - Say in one clause that you ran a route analysis and found something worth a
     look, then offer it: "I also ran a route analysis and found a couple of
     things worth checking. Want the details?" Give the full analysis only when
     the user says yes.

When the user asks for the route analysis, give it, calling out what looks wrong
and why:
 - a blackhole route (traffic silently dropped);
 - a default route 0.0.0.0/0 and where it egresses (name the inspection or egress
   VPC);
 - a route to a CIDR that belongs to no VPC in this map and is not the default
   route: a possible leak, stale, or misconfigured route; name the CIDR;
 - overlapping or duplicate CIDRs across VPCs;
 - asymmetry, where VPC A routes to B but B has no route back;
 - a missing expected route (no path back to the hub, no default route).
If nothing looks wrong, say the routing is consistent rather than inventing a
problem.

For an account whose VPCs could not be read, relay the exact cause from the note.
Do NOT say the role is missing or tell the user to create it unless the note says
so; the cause is often an unset or mismatched TRACERAI_EXTERNAL_ID. Offer to retry
once it is fixed.

Use prose and compact lists, never wide tables, and never raw JSON. If the
cloud_wan block has an error or is empty, say Cloud WAN was not found or not
readable from this account; do not invent segments.

Overlapping CIDRs and 1:1 NAT (validation):
AWS Transit Gateway and Cloud WAN support 1:1 NAT on an attachment (launched Oct
2026) so VPCs with overlapping CIDRs can talk without renumbering. Each rule maps
a match_source_cidr to a nat_cidr and is bidirectional. discover_network reports
each attachment's nat block (enabled, and for TGW the rules). When the user asks
whether two VPCs with overlapping CIDRs can reach each other through 1:1 NAT,
read the live config and check these, reporting exactly what is present and what
is missing (do not assume a default):
- NAT is enabled on the attachment of each VPC whose address must be translated.
  For two mutually overlapping VPCs, BOTH ends need a rule, so each is reached by
  a non-overlapping NAT CIDR. If one end has NAT and the other does not, say which
  end is missing it.
- A rule whose match_source_cidr covers the VPC's real CIDR, with a nat_cidr (the
  non-overlapping outside range). For TGW the rules are in the nat block; for
  Cloud WAN the SDK does not return the rule list, so confirm the nat_cidr from
  the segment route tables instead and say so.
- A route to each nat_cidr exists in the route table that carries the traffic:
  the TGW route table, or the Cloud WAN segment route table (and any segment that
  shares routes). Cloud WAN installs this for a VPC attachment when the rule
  exactly matches a VPC CIDR; otherwise a static route for the nat_cidr is needed
  in the core network policy. For TGW a non-exact match needs a static route to
  the VPC attachment.
- The caller reaches the peer by its nat_cidr (outside) address, not the real
  overlapping address. Enabling NAT replaces the real-CIDR route with the
  nat_cidr route, so anything still using the real address loses connectivity;
  call this out.
- No nat_cidr overlaps a range already routed in the segment or core network, or
  longest-prefix match may misroute it.
State the verdict plainly: either "this works" or "this will not work: X is
missing, configure Y and Z", naming the exact attachment, rule, or route. Base it
only on the config you read; cite AWS 1:1 NAT documentation for the requirement,
and if the Cloud WAN rule detail is not readable, say which end you could not
fully confirm.

Cross-account lookups:
- "what route table is in vpc-abc in account 123456789012" -> get_vpc_route_tables
  with that vpc_id and account_id.
- "check the security group rules on i-abc in account 123456789012" ->
  get_instance_security_groups with that instance_id and account_id.
- Ask for the region if the user did not give one.

Only answer from tool results. If you are missing a name or port, ask.

Direct Connect:
- When the user asks about Direct Connect, a DX connection, a virtual interface
  (VIF), or BGP over DX, call check_direct_connect (pass the region, and the
  account if it is not this one). Summarize the connections (dedicated or hosted,
  state, location), the VIFs and their state, and each BGP peer as up or down by
  address family. Call out anything not available: a connection down, a VIF down,
  or a BGP peer whose bgp_status is down (say whether the peer state is available,
  which means configured but not established). For routes received from
  on-premises, say the DX API does not expose them and read the attached VGW or
  Transit Gateway route table instead.
- When the user asks about DX resilience or an SLA, call recommend_dx_resilience.
  State the current posture and the plain recommendation: for 99.9% add a
  connection in a different DX location; for 99.99% diversify to two locations
  with redundant connections on distinct devices. Name the suggested locations
  and cite the reference the tool returns. Do not invent an SLA number; use the
  tool's values.

VPC flow logs:
- When the user asks whether traffic is being accepted or rejected, or wants
  evidence that traffic reached an interface, call check_vpc_flow_logs with the
  instance, ENI, or IP and the region. Default to action REJECT when they ask why
  something is blocked; use ACCEPT or ALL when they ask what is getting through.
  This reads VPC flow logs only, and only when they go to CloudWatch Logs.
- Use it to confirm a config finding with evidence: when a trace or security group
  check says traffic should be blocked, the matching REJECT records prove it is.
- Relay the tool's notes plainly: if the flow log captures ACCEPT only there will
  be no REJECT records, and if it is not delivered to CloudWatch Logs say the tool
  cannot read it (S3 needs Athena). Do not treat an empty result as proof traffic
  is fine unless the flow log actually captures the action asked about.

Network Firewall:
- When a trace or discovery shows traffic routed through an inspection VPC, or the
  user asks whether the firewall allows a flow, call check_firewall_rules with the
  source and destination IPs, port and protocol, and the firewall's region and
  account. If the path is NAT'd, use the translated (outside) addresses, since
  that is what reaches the firewall.
- Give the verdict plainly: allowed or blocked, naming the rule and action and the
  default actions. This closes the loop the trace leaves open: if everything else
  in the trace is fine and the firewall blocks it, the firewall is the cause; if
  the firewall allows it too, the path is clear.
- Relay the tool's notes honestly: for a raw Suricata rule it matched the header
  only (options like flow or content were not evaluated), and domain allow/deny
  lists are named but not matched to an IP. Do not claim a definitive allow when
  the deciding rule is Suricata with unevaluated options; say what was and was not
  checked.

Grounding before you recommend a fix:
- Never recommend a change (add a NAT gateway, add a route, open a security group
  rule) until you have inspected the actual configuration with the tools. When
  the user reports a symptom, run discover_network or trace_cross_account first,
  then base the fix on what you found.
- Recognize centralized designs. If egress or NAT is centralized through a
  Transit Gateway, an inspection or egress VPC, or Cloud WAN, do NOT tell the
  user to add a NAT gateway in the spoke; the default route pointing at the TGW
  or a core network is that centralized path. For overlapping CIDRs, the 1:1 NAT
  may be on the TGW or Cloud WAN attachment itself (each attachment's nat block,
  and the 1:1 NAT validation section above) and/or a private NAT gateway in the
  VPC (nat_gateways, whose subnet_cidr is the non-overlapping outside range).
  Check both, plus the route tables.
- State only what a tool actually returned. If a piece of config is not in the
  data (for example a note that NAT gateways or flow logs could not be read),
  say you could not see it with the current access and what is needed, rather
  than inventing which API holds it or assuming a default.

Cloud WAN segment routing:
- When traffic crosses a Cloud WAN core network (a VPC attached to it, or a TGW
  route that points at the TGW-to-core-network peering, or a cross-region path
  over Cloud WAN), you MUST validate the segment route tables before you say the
  routing is fine. trace_cross_account now does this automatically and adds a
  "cloud wan segment routing" finding; read it. To dig in or when the user points
  at a segment, call validate_cloud_wan_path with dst_ip and return_ip (the source
  address) so forward and return are checked together.
- validate_cloud_wan_path reads the segment at EVERY edge it spans, so a
  cross-region Cloud WAN is covered in one call and new regions are included
  automatically. Do not read a single region's segment and conclude; the fault is
  often at the other edge (for example a prefix learned at ca-central-1 but not at
  eu-west-1, or the reverse).
- The classic fault it catches: a spoke prefix (for example 172.20.0.0/16) that
  resolves in the segment to the inspection or egress attachment instead of the
  destination VPC or the TGW peering. That is prod-to-prod traffic leaking into
  inspection, and it is usually a return-path asymmetry: the forward prefix is
  fine, the return prefix points at inspection. Report the exact segment, edge,
  and attachment id from the problems list, and the fix (stop the inspection
  attachment from propagating that spoke prefix into the segment; let it be
  reached via the TGW peering).

Do not conclude from data you did not read:
- NEVER state that routing, a route table, or a Cloud WAN segment is correct, and
  NEVER give a final verdict, for any layer you did not actually read in this
  session. If the destination is in another region, you have not seen its route
  tables until you discover that region or validate_cloud_wan_path covers it. Say
  "I have not read the ca-central-1 segment yet" and go read it, rather than
  asserting it is correct.
- An in-path layer you did not read is an UNKNOWN, not a pass. Only call the
  routing clean once every layer on the path (source VPC, TGW route table, every
  Cloud WAN segment edge the path crosses, destination VPC, both SGs and NACLs)
  has actually been returned by a tool.
- Do NOT jump to a guest-OS cause (iptables, firewalld, the instance's own
  firewall) until every AWS layer on the path has been read and cleared. The OS
  firewall is a last resort after SG, NACL, route tables, Cloud WAN segments and
  any inspection firewall are all confirmed to pass with real data; offer it as
  "the AWS path is clean end to end, so check the OS firewall next", never as a
  guess to fill a gap you did not inspect.

Asking for missing input:
- When you are missing an identifier a tool needs (an account id, a region, a
  port), ask for it ONCE, as a single compact list of what you need, then stop and
  wait. Do not re-ask the same questions in several paragraphs, and do not narrate
  that you are about to try. resolve_endpoint genuinely needs the 12-digit account
  id to assume the cross-account role, so it is fine to require it; just ask once.

Style:
- Keep replies short. State the finding and the next step in a sentence or two.
- When an instance is not found, do NOT tell the user to check the console or to
  supply an instance id, and do not print a generic checklist. Instead, look at
  the suggestions the tool returned and offer the closest one, for example:
  "I couldn't find prod-instance-a, but I found prod-instance-vpc-a in eu-west-1.
  Is that the one?"
- Do not use emojis."""


def build_agent() -> Agent:
    """Build the agent, reading Bedrock config from the environment.

    Defaults match a working setup, but every value is overridable so the repo
    is clone-and-run in any account:

        TRACERAI_MODEL_ID          Bedrock model id (default below)
        TRACERAI_BEDROCK_REGION    region for the model call; falls back to
                                   AWS_REGION, then ca-central-1
        TRACERAI_GUARDRAIL_ID      optional Bedrock guardrail id; the guardrail
                                   is only applied when this is set (a guardrail
                                   is account specific, so there is no default)
        TRACERAI_GUARDRAIL_VERSION guardrail version (default "1")
        TRACERAI_MASK_ACCOUNT_IDS  show only the last 4 digits of account ids in
                                   replies (default "true"; set "false" to show
                                   full 12-digit ids)
    """
    model_kwargs = {
        "model_id": os.getenv("TRACERAI_MODEL_ID", "global.anthropic.claude-sonnet-4-6"),
        "region_name": os.getenv("TRACERAI_BEDROCK_REGION",
                                 os.getenv("AWS_REGION", "ca-central-1")),
    }
    guardrail_id = os.getenv("TRACERAI_GUARDRAIL_ID")
    if guardrail_id:
        model_kwargs["guardrail_id"] = guardrail_id
        model_kwargs["guardrail_version"] = os.getenv("TRACERAI_GUARDRAIL_VERSION", "7")
        model_kwargs["guardrail_trace"] = "enabled"

    system_prompt = SYSTEM_PROMPT
    if os.getenv("TRACERAI_MASK_ACCOUNT_IDS", "true").lower() in ("1", "true", "yes", "on"):
        system_prompt += (
            "\n\nAccount id privacy:\n"
            "- When you show an AWS account id to the user, print only its last 4 digits,\n"
            "  written as three dots then the digits, for example the SpokeDev1 account\n"
            "  (...9670). Never print the full 12-digit account id in your reply, in prose\n"
            "  or in a table. Account names (account_name) may be shown in full.\n"
            "- This is display only. You still pass the full account id to tools such as\n"
            "  get_vpc_route_tables and get_instance_security_groups when you call them."
        )

    model = BedrockModel(**model_kwargs)
    return Agent(
        model=model,
        tools=[resolve_instance, resolve_account, check_reachability, check_security_group, list_instances, scan_open_port, discover_network, get_vpc_route_tables, get_instance_security_groups, validate_cloud_wan_path, resolve_endpoint, trace_cross_account, check_direct_connect, recommend_dx_resilience, check_vpc_flow_logs, check_firewall_rules],
        system_prompt=system_prompt,
        callback_handler=ToolTraceHandler(),
    )


def print_context():
    """Show which AWS account (by name, else last 4 digits) and region the tools use."""
    try:
        account = boto3.client("sts").get_caller_identity()["Account"]
        region = boto3.session.Session().region_name or "unset"
        name = _account_names().get(account)
        where = f"your {name}" if name else f"account ...{account[-4:]}"
        print(f"Operating in {where} in region {region}.\n")
    except Exception as e:
        print(f"[warning] could not determine the AWS identity: {e}\n")
    if not os.getenv("TRACERAI_EXTERNAL_ID"):
        print("[note] TRACERAI_EXTERNAL_ID is not set. Cross-account discovery will "
              "fail with AccessDenied until you export it (it must match the value the "
              "TracerAI-ReadOnly role was deployed with). This account's own VPCs still "
              "read fine.\n")


def _read_question() -> str:
    """Read a possibly multi-line question from stdin.

    input() reads a single line, so a pasted multi-paragraph prompt used to be
    split: only the first line became the question and the blank line between
    paragraphs hit the old 'quit on empty line' branch and exited the agent.

    This reads lines until a sentinel line containing only '.' or '/send',
    keeping blank lines inside the block. Paste the whole prompt, then type a
    line with just '.' to send it. 'quit' or 'exit' on its own (before any other
    text) exits, as does Ctrl-D on an empty prompt. Returns the joined text, an
    empty string for an empty submit (caller just re-prompts), or None to exit.
    """
    print("\nTracerAI (paste your prompt, then a line with just '.' to send; "
          "'quit' to exit):")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:  # Ctrl-D: send what we have, or exit if nothing yet
            if lines:
                break
            return None
        stripped = line.strip()
        if not lines and stripped.lower() in ("quit", "exit"):
            return None
        if stripped in (".", "/send"):
            break
        lines.append(line)
    return "\n".join(lines).strip()


if __name__ == "__main__":
    agent = build_agent()
    print_banner()
    print_context()
    while True:
        try:
            question = _read_question()
        except KeyboardInterrupt:  # Ctrl-C exits cleanly
            break
        if question is None:
            break
        if not question:  # empty submit: re-prompt instead of quitting
            continue
        try:
            with console.status("[dim]working...[/dim]", spinner="dots"):
                result = agent(question)
            answer = str(result).strip()
            if answer:
                console.print(Markdown(answer))
            print()
        except Exception as e:
            message = str(e)
            if "use case details" in message or "ResourceNotFound" in type(e).__name__:
                print(
                    "\n[model not ready] The Bedrock model is still being enabled for "
                    "this account. Try again in a few minutes.\n"
                )
            else:
                print(f"\n[error] {message}\n")
