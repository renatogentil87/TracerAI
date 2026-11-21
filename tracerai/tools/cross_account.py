"""Cross-account network discovery.

Reads network config in another account by assuming a read-only role there. The
role (TracerAI-ReadOnly, see deploy/cross-account-role.yaml) must exist in the
target account and trust the account TracerAI runs in.

    python tracerai/tools/cross_account.py
"""

import boto3

from tracerai.aws_session import get_session


def _flatten_sg_rule(rule):
    """Turn a boto3 IpPermission into a simple dict."""
    sources = []
    sources += [r["CidrIp"] for r in rule.get("IpRanges", [])]
    sources += [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
    sources += [p["GroupId"] for p in rule.get("UserIdGroupPairs", [])]
    sources += [p["PrefixListId"] for p in rule.get("PrefixListIds", [])]
    return {
        "protocol": rule.get("IpProtocol", "-1"),
        "from_port": rule.get("FromPort"),
        "to_port": rule.get("ToPort"),
        "sources": sources,
    }


def _route(r):
    return {
        "destination": r.get("DestinationCidrBlock") or r.get("DestinationPrefixListId"),
        "target": (
            r.get("GatewayId") or r.get("NatGatewayId") or r.get("TransitGatewayId")
            or r.get("NetworkInterfaceId") or r.get("VpcPeeringConnectionId")
            or r.get("CoreNetworkArn")
        ),
        "state": r.get("State"),
    }


def _vpc_detail(session, vpc_id: str, region: str) -> dict:
    """Read one VPC's CIDRs, subnets, route tables, security groups and NACLs."""
    ec2 = session.client("ec2", region_name=region)
    vpc_filter = [{"Name": "vpc-id", "Values": [vpc_id]}]

    name, cidrs = None, []
    vpcs = ec2.describe_vpcs(VpcIds=[vpc_id]).get("Vpcs", [])
    if vpcs:
        v = vpcs[0]
        name = next((t["Value"] for t in v.get("Tags", []) if t["Key"] == "Name"), None)
        cidrs = [c["CidrBlock"] for c in v.get("CidrBlockAssociationSet", [])] or [v.get("CidrBlock")]

    subnets = []
    for page in ec2.get_paginator("describe_subnets").paginate(Filters=vpc_filter):
        for s in page.get("Subnets", []):
            subnets.append({"subnet_id": s["SubnetId"], "cidr": s.get("CidrBlock"), "az": s.get("AvailabilityZone")})

    route_tables = []
    for page in ec2.get_paginator("describe_route_tables").paginate(Filters=vpc_filter):
        for rt in page.get("RouteTables", []):
            route_tables.append({
                "route_table_id": rt["RouteTableId"],
                "subnets": [a.get("SubnetId") for a in rt.get("Associations", []) if a.get("SubnetId")],
                "main": any(a.get("Main") for a in rt.get("Associations", [])),
                "routes": [_route(r) for r in rt.get("Routes", [])],
            })

    security_groups = []
    for page in ec2.get_paginator("describe_security_groups").paginate(Filters=vpc_filter):
        for g in page.get("SecurityGroups", []):
            security_groups.append({
                "group_id": g["GroupId"],
                "group_name": g.get("GroupName"),
                "inbound": [_flatten_sg_rule(r) for r in g.get("IpPermissions", [])],
                "outbound": [_flatten_sg_rule(r) for r in g.get("IpPermissionsEgress", [])],
            })

    nacls = []
    for page in ec2.get_paginator("describe_network_acls").paginate(Filters=vpc_filter):
        for acl in page.get("NetworkAcls", []):
            nacls.append({
                "nacl_id": acl["NetworkAclId"],
                "subnets": [a.get("SubnetId") for a in acl.get("Associations", [])],
                "entries": [
                    {"rule": e.get("RuleNumber"), "protocol": e.get("Protocol"),
                     "action": e.get("RuleAction"), "egress": e.get("Egress"), "cidr": e.get("CidrBlock")}
                    for e in acl.get("Entries", [])
                ],
            })

    return {
        "name": name, "cidrs": cidrs, "subnets": subnets,
        "route_tables": route_tables, "security_groups": security_groups, "nacls": nacls,
    }


def discover_network(region: str = None) -> dict:
    """Map the whole network in a region, across accounts, via the TGW attachments.

    Runs in the Transit Gateway owner account. Lists every attachment, then for
    each VPC attachment reads that VPC's full detail (CIDRs, subnets, route
    tables, security groups, NACLs) in its owner account, assuming the read-only
    role when the owner is another account and using local creds for this
    account's own VPCs (shared, endpoints, centralized). Non-VPC attachments
    (VPN, peering, Direct Connect) are listed separately. An account with no role
    is reported with a note, not failed.

    Args:
        region: the region to map.

    Returns transit_gateways, vpc_attachments (each with account, vpc detail),
    and other_attachments.
    """
    if not region:
        return {"needs_region": True}

    ec2 = boto3.client("ec2", region_name=region)
    me = boto3.client("sts").get_caller_identity()["Account"]

    attachments = []
    for page in ec2.get_paginator("describe_transit_gateway_attachments").paginate():
        attachments.extend(page.get("TransitGatewayAttachments", []))

    vpc_attachments, other = [], []
    tgw_ids = []
    for a in attachments:
        tgw = a.get("TransitGatewayId")
        if tgw and tgw not in tgw_ids:
            tgw_ids.append(tgw)
        if a.get("ResourceType") != "vpc":
            other.append({
                "attachment_id": a["TransitGatewayAttachmentId"],
                "type": a.get("ResourceType"),
                "resource_id": a.get("ResourceId"),
                "account_id": a.get("ResourceOwnerId"),
            })
            continue
        account_id = a.get("ResourceOwnerId")
        vpc_id = a.get("ResourceId")
        entry = {
            "attachment_id": a["TransitGatewayAttachmentId"],
            "transit_gateway_id": tgw,
            "account_id": account_id,
            "vpc_id": vpc_id,
        }
        try:
            session = get_session(account_id=(None if account_id == me else account_id), region=region)
            entry["vpc"] = _vpc_detail(session, vpc_id, region)
        except Exception as e:
            entry["vpc"] = None
            entry["note"] = f"could not read account {account_id} (needs TracerAI-ReadOnly role): {e}"
        vpc_attachments.append(entry)

    return {
        "region": region,
        "transit_gateways": tgw_ids,
        "vpc_count": len(vpc_attachments),
        "vpc_attachments": vpc_attachments,
        "other_attachments": other,
        # TODO: add Cloud WAN discovery here (core network, segments, segment
        # route tables / RIB, attachments). Cloud WAN uses the networkmanager
        # client, not ec2, and its APIs are global (us-east-1). Fill this in.
        "cloud_wan": {},
    }


def get_vpc_route_tables(vpc_id: str, account_id: str = None, region: str = None) -> dict:
    """Read the route tables for one VPC, optionally in another account.

    Args:
        vpc_id: the VPC to read, e.g. "vpc-0abc...".
        account_id: the account that owns the VPC (optional; assumes the role).
        region: the region the VPC is in.
    """
    try:
        session = get_session(account_id=account_id, region=region)
    except Exception as e:
        return {"account_id": account_id, "vpc_id": vpc_id,
                "error": f"could not assume role in account {account_id}: {e}"}
    detail = _vpc_detail(session, vpc_id, region)
    return {"account_id": account_id, "vpc_id": vpc_id, "region": region,
            "route_tables": detail["route_tables"]}


def get_instance_security_groups(instance_id: str, account_id: str = None, region: str = None) -> dict:
    """Read the security group rules for an instance, optionally in another account.

    Args:
        instance_id: the instance id, e.g. "i-0abc...".
        account_id: the account that owns the instance (optional; assumes the role).
        region: the region the instance is in.
    """
    try:
        session = get_session(account_id=account_id, region=region)
    except Exception as e:
        return {"account_id": account_id, "instance_id": instance_id,
                "error": f"could not assume role in account {account_id}: {e}"}

    ec2 = session.client("ec2", region_name=region)
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    group_ids = []
    for res in resp.get("Reservations", []):
        for inst in res.get("Instances", []):
            group_ids += [g["GroupId"] for g in inst.get("SecurityGroups", [])]
    if not group_ids:
        return {"account_id": account_id, "instance_id": instance_id, "security_groups": []}

    groups = ec2.describe_security_groups(GroupIds=group_ids)["SecurityGroups"]
    return {
        "account_id": account_id, "instance_id": instance_id, "region": region,
        "security_groups": [
            {"group_id": g["GroupId"], "group_name": g.get("GroupName"),
             "inbound": [_flatten_sg_rule(r) for r in g.get("IpPermissions", [])],
             "outbound": [_flatten_sg_rule(r) for r in g.get("IpPermissionsEgress", [])]}
            for g in groups
        ],
    }


if __name__ == "__main__":
    import json

    # Replace with a real region to test the cross-account map.
    print(json.dumps(discover_network("eu-west-1"), indent=2))
