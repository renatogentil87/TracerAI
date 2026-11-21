"""TracerAI agent.

    python -m tracerai.agent
"""

import os

import boto3

from strands import Agent, tool
from strands.models import BedrockModel

from tracerai.tools.reachability import reachability
from tracerai.tools.instances import resolve_instance as _resolve_instance
from tracerai.tools.instances import list_instances as _list_instances
from tracerai.tools.security_groups import describe_security_group as _describe_security_group
from tracerai.tools.security_groups import scan_port as _scan_port
from tracerai.tools.cross_account import discover_network as _discover_network
from tracerai.tools.cross_account import get_vpc_route_tables as _get_vpc_route_tables
from tracerai.tools.cross_account import get_instance_security_groups as _get_instance_security_groups
from tracerai.banner import print_banner


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
def check_reachability(src_id: str, dst_id: str, port: int, region: str = None) -> dict:
    """Check whether one EC2 instance can reach another over TCP on a port.

    Requires raw instance ids. Call resolve_instance first for any friendly
    names, and pass the region it reported. Both instances must be in the same
    region.

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
        groups, NACLs) in its owner account.
      - Cloud WAN: lists core networks, their segments and (for this region's
        edge) the segment route tables, then reads each attached VPC's full
        detail in its owner account.
    It assumes the read-only role for VPCs in other accounts and uses local
    creds for this account's own VPCs (shared, endpoints, centralized). Non-VPC
    attachments (VPN, peering, Direct Connect, TGW-to-Cloud-WAN) are listed
    separately. If the user did not give a region, ask first.

    Args:
        region: the AWS region to map, e.g. "eu-west-1".

    Returns transit_gateways, vpc_attachments, other_attachments, and cloud_wan
    (core_networks with segments and vpc_attachments). An account missing the
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


SYSTEM_PROMPT = """You are TracerAI, an AWS network troubleshooting assistant.

When the user asks whether resources can connect:
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

Write the discovery answer as an explanation a network engineer would give, not
a data dump. Refer to each account by its name and id together, taking the name
from the account_name field, for example "your SpokeDev1 account (...9670) has 5
VPCs". If account_name is null, use the id alone. Work through it in this order:

1. Topology in one or two sentences. Name the pattern you see from the data: a
   hub-and-spoke Transit Gateway, a segmented Cloud WAN backbone, centralized
   egress or inspection (a default route pointing at an inspection VPC), shared
   services, or a mix. Say which backbone carries most of the traffic.
2. Attachments. State how many attachments the TGW and the core network each
   have, then list them by type: VPC attachments (name the VPC and its account),
   and non-VPC attachments (VPN, Direct Connect, peering, Connect). Then also 
   only give the route-table name, for example "You have hub-spoke TGW with 5 VPCs
   attached to each. Your Transit GAteway contains 5 route-tables, it seems it is 
   segment prod, nonprod, shared, endpoints segments, and centralizing endpoints into single vpc.
   Each VPC has a single subnet or more subnets, (list the number of subnets), and tells
   the number of route tables per subnet. Tells whether a subnet has single route, for example:
   the route table contains 3 enters, then ask if the user wants to read them or not. Do not list the entries directly
   without explicit ask from the user.
3. Cross-account. Point out which VPCs live in an account other than the one you
   are running in. If any VPC came back with a note that it could not be read,
   relay the specific cause the note gives. The note already diagnoses it: it may
   be that TRACERAI_EXTERNAL_ID is unset or does not match, that the identity
   running TracerAI lacks sts:AssumeRole, or that the role is not deployed. Do NOT
   assert the role is missing or tell the user to create it unless the note says
   so; the role may already exist and the real cause is often the external id.
   Then offer to go deeper: "N of these VPCs are in account ...NNNN, which I can't
   read yet (<the note's cause>). Want me to retry once that is fixed?"
4. Each VPC. Give its name, account, CIDR, and subnet count with AZs, then its
   route tables name, with the number of routes in each route table. 
   The ask whether the user wants to see the route table or just it.
   
   (where its default route sends traffic, which other VPCs it can reach).
5. Route analysis. This is the point of the exercise, so call out anything that
   looks wrong and say why it is strange, for example:
     - a blackhole route (traffic silently dropped);
     - a default route 0.0.0.0/0 and where it egresses (name the inspection or
       egress VPC it points at);
     - a route to a CIDR that does not belong to any VPC in this map and is not
       the default route: flag it as a possible leak, stale, or misconfigured
       route and name the CIDR;
     - overlapping or duplicate CIDRs across VPCs;
     - asymmetry, where VPC A has a route to VPC B but B has no route back to A;
     - a missing expected route (no path back to the hub, no default route).
   If everything is consistent, say so plainly rather than inventing a problem.
6. Cloud WAN segments. Summarize the segments and, from the segment route tables,
   which segments can reach which, and whether any segment is isolated or shares
   routes (the shared or endpoints segment is often reachable from all).
7. End with concrete next steps: scan another account for full detail,
   investigate a specific flagged route or blackhole, or test connectivity
   between two instances.

Use short prose and small tables. Do not print raw JSON. Be specific with ids
and CIDRs. If the cloud_wan block has an error or is empty, say Cloud WAN was not
found or not readable from this account; do not invent segments.

Cross-account lookups:
- "what route table is in vpc-abc in account 123456789012" -> get_vpc_route_tables
  with that vpc_id and account_id.
- "check the security group rules on i-abc in account 123456789012" ->
  get_instance_security_groups with that instance_id and account_id.
- Ask for the region if the user did not give one.

Only answer from tool results. If you are missing a name or port, ask.

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
        model_kwargs["guardrail_version"] = os.getenv("TRACERAI_GUARDRAIL_VERSION", "1")
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
        tools=[resolve_instance, check_reachability, check_security_group, list_instances, scan_open_port, discover_network, get_vpc_route_tables, get_instance_security_groups],
        system_prompt=system_prompt,
    )


def print_context():
    """Show which AWS account and region the tools will operate against."""
    try:
        account = boto3.client("sts").get_caller_identity()["Account"]
        region = boto3.session.Session().region_name or "unset"
        print(f"Operating against account {account} in region {region}.\n")
    except Exception as e:
        print(f"[warning] could not determine the AWS identity: {e}\n")
    if not os.getenv("TRACERAI_EXTERNAL_ID"):
        print("[note] TRACERAI_EXTERNAL_ID is not set. Cross-account discovery will "
              "fail with AccessDenied until you export it (it must match the value the "
              "TracerAI-ReadOnly role was deployed with). This account's own VPCs still "
              "read fine.\n")


if __name__ == "__main__":
    agent = build_agent()
    print_banner()
    print_context()
    while True:
        try:
            question = input("\nAsk TracerAI: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not question or question.lower() in ("quit", "exit"):
            break
        try:
            agent(question)
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
