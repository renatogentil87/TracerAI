"""TracerAI agent.

    python -m tracerai.agent
"""

import boto3

from strands import Agent, tool
from strands.models import BedrockModel

from tracerai.tools.reachability import reachability
from tracerai.tools.instances import resolve_instance as _resolve_instance
from tracerai.tools.instances import list_instances as _list_instances
from tracerai.tools.security_groups import describe_security_group as _describe_security_group
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
    model = BedrockModel(
        model_id="global.anthropic.claude-sonnet-4-6",
        region_name="ca-central-1",
    )
    return Agent(
        model=model,
        tools=[resolve_instance, check_reachability, check_security_group, list_instances],
        system_prompt=SYSTEM_PROMPT,
    )


def print_context():
    """Show which AWS account and region the tools will operate against."""
    try:
        account = boto3.client("sts").get_caller_identity()["Account"]
        region = boto3.session.Session().region_name or "unset"
        print(f"Operating against account {account} in region {region}.\n")
    except Exception as e:
        print(f"[warning] could not determine the AWS identity: {e}\n")


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
