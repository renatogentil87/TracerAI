"""
M1 — wire the M0 tool into a Strands agent. Only start this AFTER
tracerai/tools/reachability.py works standalone.

⚠️ VERIFY the Strands package name and import paths against the current Strands
   docs before relying on them (placeholders below). Run `pip install` for the
   real package into your .venv first.

Run:
    python -m tracerai.agent
"""

# ⚠️ Confirm these imports in the Strands docs:
# from strands import Agent, tool

from tracerai.tools.reachability import reachability


# @tool
def check_reachability(src_id: str, dst_id: str, port: int) -> dict:
    """Check whether one EC2 instance can reach another on a TCP port.

    The docstring IS how the model learns what this tool does and when to call
    it — keep it accurate and specific.
    """
    return reachability(src_id, dst_id, port)


def build_agent():
    """Construct the Strands Agent with the tool(s) and a system prompt.

    TODO:
      - choose the Bedrock model id (enabled in your Bedrock-allowed account)
      - write a system prompt: "You are a network troubleshooting assistant.
        When asked whether resources can connect, call check_reachability and
        explain the result (reachable + why) in plain English."
      - agent = Agent(model=..., tools=[check_reachability], system_prompt=...)
      - return agent
    """
    raise NotImplementedError("Wire up the Strands Agent (see TODOs).")


if __name__ == "__main__":
    # agent = build_agent()
    # agent("Can i-REPLACE_SRC reach i-REPLACE_DST on 3306?")
    pass
