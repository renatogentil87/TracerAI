"""Map the network layout in a region.

    python tracerai/tools/discovery.py
"""

import boto3


def discover_network(region: str = None) -> dict:
    """Discover the network layout in one region.

    Read only. Walks VPCs, their CIDRs, route tables, security groups and
    NACLs, plus Transit Gateway attachments and Transit Gateway route tables.
    Everything is paginated so nothing is missed in a large account.

    Args:
        region: the region to map. Required. When not given the result sets
            needs_region so the caller can ask the user which region.

    Returns a dict with a section per resource type (see keys below).
    """
    if not region:
        return {"needs_region": True}

    ec2 = boto3.client("ec2", region_name=region)

    result = {"region": region}

    # VPCs with their CIDRs.
    vpcs = []
    for page in ec2.get_paginator("describe_vpcs").paginate():
        for v in page.get("Vpcs", []):
            name = next((t["Value"] for t in v.get("Tags", []) if t["Key"] == "Name"), None)
            cidrs = [c["CidrBlock"] for c in v.get("CidrBlockAssociationSet", [])]
            vpcs.append({
                "vpc_id": v["VpcId"],
                "name": name,
                "cidrs": cidrs or [v.get("CidrBlock")],
            })
    result["vpcs"] = vpcs

    # VPC route tables: destinations and their targets.
    route_tables = []
    for page in ec2.get_paginator("describe_route_tables").paginate():
        for rt in page.get("RouteTables", []):
            routes = []
            for r in rt.get("Routes", []):
                routes.append({
                    "destination": r.get("DestinationCidrBlock") or r.get("DestinationPrefixListId"),
                    "target": (
                        r.get("GatewayId") or r.get("NatGatewayId")
                        or r.get("TransitGatewayId") or r.get("NetworkInterfaceId")
                        or r.get("VpcPeeringConnectionId") or r.get("CoreNetworkArn")
                    ),
                    "state": r.get("State"),
                })
            route_tables.append({
                "route_table_id": rt["RouteTableId"],
                "vpc_id": rt.get("VpcId"),
                "subnets": [a.get("SubnetId") for a in rt.get("Associations", []) if a.get("SubnetId")],
                "main": any(a.get("Main") for a in rt.get("Associations", [])),
                "routes": routes,
            })
    result["route_tables"] = route_tables

    # Security groups: inbound and outbound rules.
    security_groups = []
    for page in ec2.get_paginator("describe_security_groups").paginate():
        for g in page.get("SecurityGroups", []):
            security_groups.append({
                "group_id": g["GroupId"],
                "group_name": g.get("GroupName"),
                "vpc_id": g.get("VpcId"),
                "inbound": [_flatten_sg_rule(r) for r in g.get("IpPermissions", [])],
                "outbound": [_flatten_sg_rule(r) for r in g.get("IpPermissionsEgress", [])],
            })
    result["security_groups"] = security_groups

    # NACLs: entries per subnet association.
    nacls = []
    for page in ec2.get_paginator("describe_network_acls").paginate():
        for acl in page.get("NetworkAcls", []):
            nacls.append({
                "nacl_id": acl["NetworkAclId"],
                "vpc_id": acl.get("VpcId"),
                "subnets": [a.get("SubnetId") for a in acl.get("Associations", [])],
                "entries": [
                    {
                        "rule": e.get("RuleNumber"),
                        "protocol": e.get("Protocol"),
                        "action": e.get("RuleAction"),
                        "egress": e.get("Egress"),
                        "cidr": e.get("CidrBlock"),
                    }
                    for e in acl.get("Entries", [])
                ],
            })
    result["nacls"] = nacls

    # Transit Gateway attachments.
    tgw_attachments = []
    for page in ec2.get_paginator("describe_transit_gateway_attachments").paginate():
        for a in page.get("TransitGatewayAttachments", []):
            tgw_attachments.append({
                "attachment_id": a["TransitGatewayAttachmentId"],
                "transit_gateway_id": a.get("TransitGatewayId"),
                "resource_type": a.get("ResourceType"),
                "resource_id": a.get("ResourceId"),
                "state": a.get("State"),
            })
    result["tgw_attachments"] = tgw_attachments

    # Transit Gateway route tables (the tables themselves; routes are a separate
    # search per table, which this tool leaves to the dedicated TGW route tool).
    tgw_route_tables = []
    for page in ec2.get_paginator("describe_transit_gateway_route_tables").paginate():
        for rt in page.get("TransitGatewayRouteTables", []):
            name = next((t["Value"] for t in rt.get("Tags", []) if t["Key"] == "Name"), None)
            tgw_route_tables.append({
                "route_table_id": rt["TransitGatewayRouteTableId"],
                "transit_gateway_id": rt.get("TransitGatewayId"),
                "name": name,
                "default_association": rt.get("DefaultAssociationRouteTable"),
                "default_propagation": rt.get("DefaultPropagationRouteTable"),
                "state": rt.get("State"),
            })
    result["tgw_route_tables"] = tgw_route_tables

    # --- Cloud WAN ---
    # TODO: add Cloud WAN discovery here (core network, segments, segment route
    # tables / RIB, attachments). Cloud WAN uses the networkmanager client, not
    # ec2, and its APIs are global (us-east-1). Fill this section in.
    result["cloud_wan"] = {}

    return result


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


if __name__ == "__main__":
    import json

    # Replace with a real region to test.
    print(json.dumps(discover_network("eu-west-1"), indent=2))
