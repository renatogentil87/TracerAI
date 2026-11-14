"""Resolve an EC2 Name tag to an instance id.

    python tracerai/tools/instances.py
"""

import boto3


def resolve_instance(name: str) -> dict:
    """Resolve an EC2 instance by its Name tag, or pass through a raw id.

    Args:
        name: the instance's "Name" tag value (e.g. "web-server"), or a raw
            instance id like "i-0abc..." (returned as-is).

    Returns:
        {
          "matches": [{"instance_id": "i-...", "name": "web-server", "state": "running"}],
          "resolved_id": "i-..."  # set only when exactly one running match
        }
    """
    ec2 = boto3.client("ec2")

    if name.startswith("i-"):
        return {
            "matches": [{"instance_id": name, "name": None, "state": None}],
            "resolved_id": name,
        }

    resp = ec2.describe_instances(
        Filters=[{"Name": "tag:Name", "Values": [name]}],
    )

    matches = []
    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            name_tag = next(
                (t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"),
                None,
            )
            matches.append({
                "instance_id": inst["InstanceId"],
                "name": name_tag,
                "state": inst["State"]["Name"],
            })

    running = [m for m in matches if m["state"] == "running"]
    resolved_id = running[0]["instance_id"] if len(running) == 1 else None

    return {"matches": matches, "resolved_id": resolved_id}


if __name__ == "__main__":
    import json

    print(json.dumps(resolve_instance("REPLACE_WITH_NAME_TAG"), indent=2))
