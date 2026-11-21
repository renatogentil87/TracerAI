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


def _parse_vpc_arn(arn: str):
    """Pull region, account id and vpc id out of a VPC ARN.

    arn:aws:ec2:<region>:<account>:vpc/<vpc-id>
    """
    try:
        parts = arn.split(":")
        region = parts[3]
        account = parts[4]
        vpc_id = parts[5].split("/")[-1]
        return region, account, vpc_id
    except Exception:
        return None, None, None


def _nm_paginate(func, key: str, **kwargs):
    """Collect every page from a networkmanager list call (NextToken based)."""
    items, token = [], None
    while True:
        if token:
            kwargs["NextToken"] = token
        resp = func(**kwargs)
        items.extend(resp.get(key, []))
        token = resp.get("NextToken")
        if not token:
            break
    return items


def _account_names():
    """Map account id -> account name via AWS Organizations.

    Works when the caller can read Organizations (the management account or a
    delegated administrator). Returns an empty dict if that call is not allowed,
    so discovery still works, just without friendly names.
    """
    names = {}
    try:
        org = boto3.client("organizations", region_name="us-east-1")
        for page in org.get_paginator("list_accounts").paginate():
            for a in page.get("Accounts", []):
                names[a["Id"]] = a.get("Name")
    except Exception:
        pass
    return names


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
    acct_names = _account_names()

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
                "account_name": acct_names.get(a.get("ResourceOwnerId")),
            })
            continue
        account_id = a.get("ResourceOwnerId")
        vpc_id = a.get("ResourceId")
        entry = {
            "attachment_id": a["TransitGatewayAttachmentId"],
            "transit_gateway_id": tgw,
            "account_id": account_id,
            "account_name": acct_names.get(account_id),
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
        "cloud_wan": discover_cloud_wan(region, account_names=acct_names),
    }


def discover_cloud_wan(region: str = None, account_names: dict = None) -> dict:
    """Discover AWS Cloud WAN in a region, across accounts.

    Cloud WAN's control plane (networkmanager) is global, so the client is
    pinned to us-east-1. Runs in the core network owner account (local creds).
    For each core network it reads the segments and, for the requested region's
    edge, the segment route tables (RIB). For every VPC attachment in the
    requested region it reads that VPC's full detail (CIDRs, subnets, route
    tables, security groups, NACLs) in the VPC's owner account, assuming the
    read-only role cross-account and using local creds for this account's own
    VPCs. Non-VPC attachments (TGW, Connect, VPN, SD-WAN) are listed separately.
    An account with no read-only role is reported with a note, not failed.

    Args:
        region: the region (Cloud WAN edge location) to map.

    Returns core_networks, each with segments, vpc_attachments (account + full
    VPC detail) and other_attachments.
    """
    nm = boto3.client("networkmanager", region_name="us-east-1")
    me = boto3.client("sts").get_caller_identity()["Account"]
    if account_names is None:
        account_names = _account_names()

    try:
        core_networks = _nm_paginate(nm.list_core_networks, "CoreNetworks")
    except Exception as e:
        return {"error": f"could not list core networks: {e}", "core_networks": []}

    result = []
    for cn in core_networks:
        core_network_id = cn.get("CoreNetworkId")
        entry = {
            "core_network_id": core_network_id,
            "global_network_id": cn.get("GlobalNetworkId"),
            "owner_account_id": cn.get("OwnerAccountId"),
            "state": cn.get("State"),
            "segments": [],
            "vpc_attachments": [],
            "other_attachments": [],
        }

        # Segments and the edges each one spans.
        try:
            detail = nm.get_core_network(CoreNetworkId=core_network_id)["CoreNetwork"]
            for seg in detail.get("Segments", []):
                entry["segments"].append({
                    "name": seg.get("Name"),
                    "edge_locations": seg.get("EdgeLocations", []),
                    "shared_segments": seg.get("SharedSegments", []),
                })
        except Exception as e:
            entry["segments_note"] = f"could not read core network detail: {e}"

        # Segment route tables (RIB) for the requested region's edge.
        global_network_id = cn.get("GlobalNetworkId")
        if region and global_network_id:
            for seg in entry["segments"]:
                if region not in (seg.get("edge_locations") or []):
                    continue
                try:
                    routes = nm.get_network_routes(
                        GlobalNetworkId=global_network_id,
                        RouteTableIdentifier={
                            "CoreNetworkSegmentEdge": {
                                "CoreNetworkId": core_network_id,
                                "SegmentName": seg["name"],
                                "EdgeLocation": region,
                            }
                        }
                    )
                    seg["routes"] = [
                        {
                            "destination": r.get("DestinationCidrBlock"),
                            "state": r.get("State"),
                            "type": r.get("Type"),
                            "targets": [
                                {
                                    "segment": d.get("SegmentName"),
                                    "edge_location": d.get("EdgeLocation"),
                                    "resource_type": d.get("ResourceType"),
                                    "resource_id": d.get("ResourceId"),
                                    "attachment_id": d.get("CoreNetworkAttachmentId"),
                                }
                                for d in r.get("Destinations", [])
                            ],
                        }
                        for r in routes.get("NetworkRoutes", [])
                    ]
                except Exception as e:
                    seg["routes_note"] = f"could not read segment route table: {e}"

        # Attachments (VPC detail read in each VPC's owner account).
        try:
            attachments = _nm_paginate(nm.list_attachments, "Attachments",
                                       CoreNetworkId=core_network_id)
        except Exception as e:
            entry["attachments_note"] = f"could not list attachments: {e}"
            result.append(entry)
            continue

        for a in attachments:
            a_type = a.get("AttachmentType")
            edge = a.get("EdgeLocation")
            if a_type == "VPC":
                vregion, account_id, vpc_id = _parse_vpc_arn(a.get("ResourceArn", ""))
                vregion = vregion or edge
                if region and vregion != region:
                    continue
                vatt = {
                    "attachment_id": a.get("AttachmentId"),
                    "segment": a.get("SegmentName"),
                    "edge_location": edge,
                    "account_id": account_id,
                    "account_name": account_names.get(account_id),
                    "vpc_id": vpc_id,
                    "state": a.get("State"),
                }
                try:
                    session = get_session(
                        account_id=(None if account_id == me else account_id),
                        region=vregion)
                    vatt["vpc"] = _vpc_detail(session, vpc_id, vregion)
                except Exception as e:
                    vatt["vpc"] = None
                    vatt["note"] = (f"could not read account {account_id} "
                                    f"(needs TracerAI-ReadOnly role): {e}")
                entry["vpc_attachments"].append(vatt)
            else:
                if region and edge and edge != region:
                    continue
                entry["other_attachments"].append({
                    "attachment_id": a.get("AttachmentId"),
                    "type": a_type,
                    "segment": a.get("SegmentName"),
                    "edge_location": edge,
                    "resource_arn": a.get("ResourceArn"),
                    "account_id": a.get("OwnerAccountId"),
                    "account_name": account_names.get(a.get("OwnerAccountId")),
                })
        result.append(entry)

    return {"core_networks": result}


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
