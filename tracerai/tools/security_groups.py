"""Inspect EC2 security group rules.

    python tracerai/tools/security_groups.py
"""

import boto3


def describe_security_group(target: str, port: int = None, protocol: str = "tcp", region: str = None) -> dict:
    """Return the security group rules for an instance or a security group.

    Args:
        target: an instance id (i-...) or a security group id (sg-...). If it is
            an instance, all of its security groups are inspected.
        port: optional. When given, the result also says whether that inbound
            port is allowed and which rules matched.
        protocol: "tcp" (default) or "udp". Only used with port.
        region: optional region the resource lives in. Pass the region from
            resolve_instance so the lookup targets the right place.

    Returns:
        {
          "security_groups": [
            {
              "group_id": "sg-...",
              "group_name": "prod-sg",
              "inbound":  [{"protocol": "tcp", "from_port": 22, "to_port": 22,
                            "sources": ["1.2.3.4/32"]}],
              "outbound": [{"protocol": "-1", "from_port": None, "to_port": None,
                            "sources": ["0.0.0.0/0"]}]
            }
          ],
          "port_check": {"port": 1010, "protocol": "tcp",
                         "allowed_inbound": False, "matched": []}   # only if port given
        }
    """
    ec2 = boto3.client("ec2", region_name=region) if region else boto3.client("ec2")

    # Work out which security groups to look at.
    if target.startswith("sg-"):
        group_ids = [target]
    elif target.startswith("i-"):
        resp = ec2.describe_instances(InstanceIds=[target])
        group_ids = []
        for reservation in resp.get("Reservations", []):
            for inst in reservation.get("Instances", []):
                group_ids += [g["GroupId"] for g in inst.get("SecurityGroups", [])]
    else:
        raise ValueError("target must be an instance id (i-...) or security group id (sg-...)")

    groups = ec2.describe_security_groups(GroupIds=group_ids)["SecurityGroups"]

    security_groups = []
    for g in groups:
        security_groups.append({
            "group_id": g["GroupId"],
            "group_name": g.get("GroupName"),
            "inbound": [_flatten_rule(r) for r in g.get("IpPermissions", [])],
            "outbound": [_flatten_rule(r) for r in g.get("IpPermissionsEgress", [])],
        })

    result = {"security_groups": security_groups}

    # Optional: does an inbound rule allow this port?
    if port is not None:
        matched = []
        for sg in security_groups:
            for rule in sg["inbound"]:
                if _rule_allows(rule, port, protocol):
                    matched.append({"group_id": sg["group_id"], "rule": rule})
        result["port_check"] = {
            "port": port,
            "protocol": protocol,
            "allowed_inbound": len(matched) > 0,
            "matched": matched,
        }

    return result


def _flatten_rule(rule):
    """Turn a boto3 IpPermission into a simple dict."""
    proto = rule.get("IpProtocol", "-1")
    sources = []
    sources += [r["CidrIp"] for r in rule.get("IpRanges", [])]
    sources += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
    sources += [p["GroupId"] for p in rule.get("UserIdGroupPairs", [])]
    sources += [p["PrefixListId"] for p in rule.get("PrefixListIds", [])]
    return {
        "protocol": proto,
        "from_port": rule.get("FromPort"),
        "to_port": rule.get("ToPort"),
        "sources": sources,
    }


def _rule_allows(rule, port, protocol):
    """True if a flattened rule permits the given port and protocol."""
    proto = rule["protocol"]
    # "-1" means every protocol and every port.
    if proto == "-1":
        return True
    if proto != protocol:
        return False
    # A rule with no ports covers the whole range for that protocol.
    if rule["from_port"] is None or rule["to_port"] is None:
        return True
    return rule["from_port"] <= port <= rule["to_port"]


def scan_port(port: int, protocol: str = "tcp", region: str = None) -> dict:
    """Scan every security group in a region for an open inbound port.

    Answers "is port X open in any security group here". Paginates over all
    security groups so nothing is missed in a large account.

    Args:
        port: the inbound port to look for, e.g. 22.
        protocol: "tcp" (default) or "udp".
        region: optional region to scan. Pass the region the user named.

    Returns:
        {
          "port": 22, "protocol": "tcp", "region": "eu-west-1",
          "open": True,
          "matches": [
            {"group_id": "sg-...", "group_name": "prod-sg",
             "sources": ["0.0.0.0/0"],
             "rule": {"protocol": "tcp", "from_port": 22, "to_port": 22,
                      "sources": ["0.0.0.0/0"]}}
          ]
        }
        When nothing matches, open is False and matches is empty.
    """
    ec2 = boto3.client("ec2", region_name=region) if region else boto3.client("ec2")

    matches = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for g in page.get("SecurityGroups", []):
            for raw in g.get("IpPermissions", []):
                rule = _flatten_rule(raw)
                if _rule_allows(rule, port, protocol):
                    matches.append({
                        "group_id": g["GroupId"],
                        "group_name": g.get("GroupName"),
                        "sources": rule["sources"],
                        "rule": rule,
                    })

    return {
        "port": port,
        "protocol": protocol,
        "region": region,
        "open": len(matches) > 0,
        "matches": matches,
    }


if __name__ == "__main__":
    import json

    # Replace with a real instance id or sg id, and an optional port to check.
    print(json.dumps(describe_security_group("i-REPLACE_ME", port=22), indent=2))
