"""Cross-account network discovery.

Reads network config in another account by assuming a read-only role there. The
role (TracerAI-ReadOnly, see deploy/cross-account-role.yaml) must exist in the
target account and trust the account TracerAI runs in.

    python tracerai/tools/cross_account.py
"""

import boto3

from tracerai.aws_session import get_session


def get_vpc_route_tables(vpc_id: str, account_id: str = None, region: str = None) -> dict:
    """Read the route tables for one VPC, optionally in another account.

    Args:
        vpc_id: the VPC to read, e.g. "vpc-0abc...".
        account_id: the account that owns the VPC. When given, assume the
            read-only role in that account; when omitted, use current creds.
        region: the region the VPC is in.

    Returns the VPC's route tables with routes, or an error note when the role
    could not be assumed.
    """
    try:
        session = get_session(account_id=account_id, region=region)
    except Exception as e:
        return {
            "account_id": account_id,
            "vpc_id": vpc_id,
            "error": f"could not assume role in account {account_id}: {e}",
        }

    ec2 = session.client("ec2", region_name=region)
    tables = []
    paginator = ec2.get_paginator("describe_route_tables")
    for page in paginator.paginate(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]):
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
            tables.append({
                "route_table_id": rt["RouteTableId"],
                "subnets": [a.get("SubnetId") for a in rt.get("Associations", []) if a.get("SubnetId")],
                "main": any(a.get("Main") for a in rt.get("Associations", [])),
                "routes": routes,
            })
    return {"account_id": account_id, "vpc_id": vpc_id, "region": region, "route_tables": tables}


def discover_via_attachments(region: str = None) -> dict:
    """Map the network across accounts using the TGW attachments as the index.

    Runs in the Transit Gateway owner account. Lists the VPC attachments to find
    every connected VPC and its owner account, then for each one reads that VPC's
    route tables (assuming the read-only role when the owner is another account).
    An account with no role is reported with a note, not failed.

    Args:
        region: the region to map.

    Returns a per-attachment list with each VPC's route tables, or a note where
    the owner account could not be read.
    """
    if not region:
        return {"needs_region": True}

    ec2 = boto3.client("ec2", region_name=region)
    me = boto3.client("sts").get_caller_identity()["Account"]

    results = []
    paginator = ec2.get_paginator("describe_transit_gateway_attachments")
    for page in paginator.paginate():
        for a in page.get("TransitGatewayAttachments", []):
            if a.get("ResourceType") != "vpc":
                continue
            account_id = a.get("ResourceOwnerId")
            vpc_id = a.get("ResourceId")
            entry = {
                "attachment_id": a["TransitGatewayAttachmentId"],
                "account_id": account_id,
                "vpc_id": vpc_id,
            }
            # Same account as us: read locally. Another account: assume the role.
            target = None if account_id == me else account_id
            rt = get_vpc_route_tables(vpc_id, account_id=target, region=region)
            if "error" in rt:
                entry["route_tables"] = None
                entry["note"] = rt["error"]
            else:
                entry["route_tables"] = rt["route_tables"]
            results.append(entry)
    return {"region": region, "attachments": results}


if __name__ == "__main__":
    import json

    # Replace with a real region to test the attachment-driven map.
    print(json.dumps(discover_via_attachments("eu-west-1"), indent=2))
