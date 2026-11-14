"""
M2 tool — resolve a friendly EC2 "Name" tag to an instance id, so the agent can
answer questions like "can the web server reach the database?" instead of
requiring raw i-xxxx ids.

Plain boto3, independently testable:
    python tracerai/tools/instances.py
"""

import boto3


def resolve_instance(name: str) -> dict:
    """Resolve an EC2 instance by its Name tag (or by raw instance id).

    Args:
        name: the value of the instance's "Name" tag (e.g. "web-server"),
              or a raw instance id like "i-0abc..." (returned as-is if it
              already looks like an id).

    Returns a clean dict:
        {
          "matches": [
            {"instance_id": "i-...", "name": "web-server", "state": "running"},
            ...
          ],
          "resolved_id": "i-..."  # set only when exactly ONE running match
        }
    The agent should ask the user to disambiguate when matches has more than one
    entry, and should treat resolved_id as the id to pass to reachability().
    """
    ec2 = boto3.client("ec2")

    # If it already looks like an instance id, don't bother searching.
    if name.startswith("i-"):
        return {"matches": [{"instance_id": name, "name": None, "state": None}],
                "resolved_id": name}

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
    # Replace with a Name tag that exists in your account:
    print(json.dumps(resolve_instance("REPLACE_WITH_NAME_TAG"), indent=2))
