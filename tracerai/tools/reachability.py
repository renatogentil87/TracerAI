"""
M0 — EC2 Reachability Analyzer tool (PLAIN boto3, no AI yet).

Goal of this file: one function you can run on its own and trust BEFORE any
agent is involved. Get this green first.

API flow (see the three calls below):
    1. ec2.create_network_insights_path(...)      -> returns a path id  (nip-...)
    2. ec2.start_network_insights_analysis(...)    -> returns an analysis id (nia-...), ASYNC
    3. ec2.describe_network_insights_analyses(...) -> poll until Status == 'succeeded'

Extract from the succeeded analysis:
    NetworkPathFound        -> True/False  (the headline answer)
    Explanations[]          -> structured WHY, each with an ExplanationCode
    ForwardPathComponents[] -> hop-by-hop path (SG, route table, NACL, ENI...)

Return a CLEAN dict (not the raw boto3 blob) so the LLM in M1 can explain it
reliably. Shape the output here — that is 80% of a good agent.

Run standalone:
    python tracerai/tools/reachability.py
"""

import boto3


def reachability(src_id: str, dst_id: str, port: int, protocol: str = "tcp") -> dict:
    """Return whether src_id can reach dst_id on the given TCP/UDP port.

    Args:
        src_id:   source instance id (or ENI/IGW/etc.)
        dst_id:   destination instance id
        port:     destination port, e.g. 3306
        protocol: "tcp" (default) or "udp"

    Returns a clean dict, e.g.:
        {
          "reachable": False,
          "reason_codes": ["ENI_SG_RULES_MISMATCH"],
          "blocked_at": "<component from the explanation>",
          "path_summary": [ ...trimmed hop list... ],
        }
    """
    ec2 = boto3.client("ec2")  # uses your shell's AWS creds / sandbox role

    # TODO 1: create_network_insights_path(Source, Destination, Protocol, DestinationPort)
    #         -> capture NetworkInsightsPath.NetworkInsightsPathId

    # TODO 2: start_network_insights_analysis(NetworkInsightsPathId=...)
    #         -> capture NetworkInsightsAnalysis.NetworkInsightsAnalysisId

    # TODO 3: poll describe_network_insights_analyses(NetworkInsightsAnalysisIds=[...])
    #         until Status == 'succeeded' (check for a boto3 waiter first;
    #         else a capped while-loop with a short sleep)

    # TODO 4: build and return the CLEAN dict from NetworkPathFound + Explanations

    # TODO 5 (cleanup): delete_network_insights_path(...) so paths/analyses don't
    #         accumulate (cost/quota). Or reuse paths deliberately.

    raise NotImplementedError("Implement the Reachability Analyzer flow (TODOs 1-5).")


if __name__ == "__main__":
    # M0 self-test: use two instances you own — one PASS case and one FAIL case
    # (e.g. a port the destination SG does not allow) so you see real
    # ExplanationCodes. Print the result.
    #
    # Example (fill in real ids):
    #   print(reachability("i-REPLACE_SRC", "i-REPLACE_DST", 3306))
    pass
