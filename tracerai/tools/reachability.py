"""EC2 Reachability Analyzer wrapper.

    python tracerai/tools/reachability.py
"""

import time
import boto3


def reachability(src_id: str, dst_id: str, port: int, protocol: str = "tcp") -> dict:
    """Return whether src_id can reach dst_id on the given port.

    Args:
        src_id: source instance id (or ENI/IGW/etc.)
        dst_id: destination instance id
        port: destination port, e.g. 3306
        protocol: "tcp" (default) or "udp"

    Returns:
        {
          "reachable": False,
          "reason_codes": ["ENI_SG_RULES_MISMATCH"],
          "path_summary": ["i-...", "sg-...", "rtb-...", "i-..."],
          "analysis_id": "nia-...",
        }
    """
    ec2 = boto3.client("ec2")
    path_id = None

    try:
        path = ec2.create_network_insights_path(
            Source=src_id,
            Destination=dst_id,
            Protocol=protocol,
            DestinationPort=port,
        )
        path_id = path["NetworkInsightsPath"]["NetworkInsightsPathId"]

        started = ec2.start_network_insights_analysis(
            NetworkInsightsPathId=path_id,
        )
        analysis_id = started["NetworkInsightsAnalysis"]["NetworkInsightsAnalysisId"]

        analysis = _poll_until_done(ec2, analysis_id)

        reachable = bool(analysis.get("NetworkPathFound", False))
        reason_codes = [
            e["ExplanationCode"]
            for e in analysis.get("Explanations", [])
            if "ExplanationCode" in e
        ]
        path_summary = _summarize_path(analysis.get("ForwardPathComponents", []))

        return {
            "reachable": reachable,
            "reason_codes": reason_codes,
            "path_summary": path_summary,
            "analysis_id": analysis_id,
        }

    finally:
        if path_id:
            try:
                ec2.delete_network_insights_path(NetworkInsightsPathId=path_id)
            except Exception:
                pass


def _poll_until_done(ec2, analysis_id, max_attempts=30, delay_seconds=2):
    for _ in range(max_attempts):
        resp = ec2.describe_network_insights_analyses(
            NetworkInsightsAnalysisIds=[analysis_id],
        )
        analysis = resp["NetworkInsightsAnalyses"][0]
        status = analysis["Status"]
        if status == "succeeded":
            return analysis
        if status == "failed":
            raise RuntimeError(
                f"Analysis {analysis_id} failed: {analysis.get('StatusMessage', 'no detail')}"
            )
        time.sleep(delay_seconds)
    raise TimeoutError(
        f"Analysis {analysis_id} did not finish within {max_attempts * delay_seconds}s"
    )


def _summarize_path(components):
    hops = []
    for c in components:
        res = c.get("Component", {})
        hops.append(res.get("Id") or res.get("Arn") or "?")
    return hops


if __name__ == "__main__":
    import json

    print(json.dumps(reachability("i-REPLACE_SRC", "i-REPLACE_DST", 22), indent=2))
