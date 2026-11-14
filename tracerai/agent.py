"""
M1 — the Strands agent. Run AFTER tracerai/tools/reachability.py works.

Install (verified package names):
    pip install strands-agents strands-agents-tools

Run:
    python -m tracerai.agent
"""

# `Agent` is the orchestrator (owns the loop + model I/O).
# `tool` is the decorator that turns a plain function into something the model
# can call. Strands reads the function's TYPE HINTS (parameter schema) and its
# DOCSTRING (what the tool does / when to use it) — so both matter.
from strands import Agent, tool

# Optional: a specific Bedrock model. Omit `model=` entirely to use the Strands
# default (a Claude model on Bedrock). Shown here so you see where it goes.
from strands.models import BedrockModel

from tracerai.tools.reachability import reachability


@tool
def check_reachability(src_id: str, dst_id: str, port: int) -> dict:
    """Check whether one EC2 instance can reach another over TCP on a port.

    Use this whenever the user asks if one resource can connect to / reach /
    talk to another, or why a connection is failing.

    Args:
        src_id: the SOURCE EC2 instance id, e.g. "i-0abc..."
        dst_id: the DESTINATION EC2 instance id, e.g. "i-0def..."
        port:   the destination TCP port, e.g. 3306 for MySQL, 22 for SSH

    Returns a dict with `reachable` (bool), `reason_codes` (why, if blocked),
    and `path_summary` (the hops the traffic would take).
    """
    # The @tool wrapper is intentionally thin: it just calls your tested M0
    # function. Keep tools dumb; keep the real logic in tools/.
    return reachability(src_id, dst_id, port)


SYSTEM_PROMPT = """You are TracerAI, an AWS network troubleshooting assistant.
When the user asks whether resources can connect, call check_reachability with
the instance IDs and port, then explain the result in plain English:
- say clearly whether it is reachable,
- if it is blocked, name the reason from reason_codes in human terms
  (e.g. ENI_SG_RULES_MISMATCH = a security group doesn't allow that port),
- suggest the most likely fix.
Only answer from tool results. If you are missing an instance ID or port, ask."""


def build_agent() -> Agent:
    # Pick a model enabled in YOUR Bedrock-allowed account. Swap this id for one
    # you have model access to, or delete `model=` to take the Strands default.
    # Claude Sonnet 5.5 — verified ACTIVE in ca-central-1 under rrdog-terraform.
    # This model is INFERENCE_PROFILE-only, so we use the profile id (not the
    # bare "anthropic.claude-sonnet-5-5", which cannot be invoked directly).
    model = BedrockModel(model_id="us.anthropic.claude-sonnet-5-5")

    return Agent(
        model=model,
        tools=[check_reachability],
        system_prompt=SYSTEM_PROMPT,
    )


if __name__ == "__main__":
    agent = build_agent()
    # Calling the agent with a string runs the full loop and prints/returns the
    # final answer. Replace with real instance IDs you own.
    agent("Can i-REPLACE_SRC reach i-REPLACE_DST on port 22?")
