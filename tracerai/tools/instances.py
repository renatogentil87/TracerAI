"""Resolve an EC2 instance by its Name tag.

    python tracerai/tools/instances.py
"""

import boto3

# Regions searched when the caller does not name one.
DEFAULT_REGIONS = ["eu-west-1", "ca-central-1", "us-east-1"]


def resolve_instance(name: str, region: str = None) -> dict:
    """Find EC2 instances whose Name tag matches, case insensitive and partial.

    Args:
        name: a full or partial Name tag (case insensitive), or a raw instance
            id like "i-0abc..." which is returned as is.
        region: optional region to search. When omitted, a default set of regions
            is searched so the caller does not need to know where it lives.

    Returns:
        {
          "matches": [
            {"instance_id": "i-...", "name": "prod-instance-a",
             "state": "running", "region": "ca-central-1"}
          ],
          "resolved_id": "i-..."  # set only when exactly one running match
        }
    """
    if name.startswith("i-"):
        return {
            "matches": [{"instance_id": name, "name": None, "state": None, "region": region}],
            "resolved_id": name,
        }

    regions = [region] if region else DEFAULT_REGIONS
    needle = name.lower()
    matches = []
    discovered = []

    for r in regions:
        ec2 = boto3.client("ec2", region_name=r)
        for reservation in ec2.describe_instances().get("Reservations", []):
            for inst in reservation.get("Instances", []):
                name_tag = next(
                    (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                    None,
                )
                entry = {
                    "instance_id": inst["InstanceId"],
                    "name": name_tag,
                    "state": inst["State"]["Name"],
                    "region": r,
                }
                discovered.append(entry)
                if name_tag and needle in name_tag.lower():
                    matches.append(entry)

    running = [m for m in matches if m["state"] == "running"]
    resolved_id = running[0]["instance_id"] if len(running) == 1 else None

    result = {"matches": matches, "resolved_id": resolved_id}
    # When nothing matched, hand back what we DID find so the agent can offer
    # the closest alternative instead of a dead end.
    if not matches:
        result["suggestions"] = discovered
    return result


if __name__ == "__main__":
    import json

    # A partial name works now, e.g. "prod" matches prod-instance-a, prod-instance-vpc-a, etc.
    print(json.dumps(resolve_instance("prod"), indent=2))
