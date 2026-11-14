"""TracerAI agent.

    python -m tracerai.agent
"""

from strands import Agent, tool
from strands.models import BedrockModel

from tracerai.tools.reachability import reachability
from tracerai.tools.instances import resolve_instance as _resolve_instance


@tool
def resolve_instance(name: str) -> dict:
    """Resolve an EC2 instance by its Name tag to an instance id.

    Call this when the user refers to an instance by name rather than an
    i-xxxx id. Returns `matches` (all instances with that Name) and
    `resolved_id` (set only when there is exactly one running match). Ask the
    user to pick when there are multiple matches.

    Args:
        name: the instance's Name tag, or a raw instance id.
    """
    return _resolve_instance(name)


@tool
def check_reachability(src_id: str, dst_id: str, port: int) -> dict:
    """Check whether one EC2 instance can reach another over TCP on a port.

    Requires raw instance ids. Call resolve_instance first for any friendly
    names.

    Args:
        src_id: source instance id, e.g. "i-0abc..."
        dst_id: destination instance id, e.g. "i-0def..."
        port: destination TCP port, e.g. 3306 (MySQL), 22 (SSH)

    Returns `reachable`, `reason_codes`, and `path_summary`.
    """
    return reachability(src_id, dst_id, port)


SYSTEM_PROMPT = """You are TracerAI, an AWS network troubleshooting assistant.

When the user asks whether resources can connect:
1. If they named an instance by a friendly name (not an i-xxxx id), call
   resolve_instance to get its id, for both source and destination.
   If there are multiple matches, ask the user which one. If none, say so.
2. Once you have both ids, call check_reachability with the port
   (infer common ports from service names: SSH=22, MySQL=3306, HTTPS=443).
3. Explain the result in plain English: whether it is reachable, and if
   blocked, translate reason_codes into human terms (for example
   ENI_SG_RULES_MISMATCH means a security group does not allow that port)
   and suggest the most likely fix.

Only answer from tool results. If you are missing a name or port, ask."""


def build_agent() -> Agent:
    model = BedrockModel(
        model_id="us.anthropic.claude-sonnet-4-6",
        region_name="ca-central-1",
    )
    return Agent(
        model=model,
        tools=[resolve_instance, check_reachability],
        system_prompt=SYSTEM_PROMPT,
    )


if __name__ == "__main__":
    agent = build_agent()
    print("TracerAI: ask a network question (type 'quit' to exit).")
    while True:
        try:
            question = input("\nAsk TracerAI: ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not question or question.lower() in ("quit", "exit"):
            break
        agent(question)
