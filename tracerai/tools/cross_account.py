"""Cross-account network discovery.

Reads network config in another account by assuming a read-only role there. The
role (TracerAI-ReadOnly, see deploy/cross-account-role.yaml) must exist in the
target account and trust the account TracerAI runs in.

    python tracerai/tools/cross_account.py
"""

import ipaddress
import os
import re

import boto3

from tracerai.aws_session import get_session


def _assume_failure_note(account_id: str, exc: Exception) -> str:
    """Turn an assume-role/read failure into an accurate diagnosis.

    The old message always blamed a missing role, which is wrong when the real
    cause is a missing or mismatched external id or a caller without
    sts:AssumeRole. STS deliberately returns the same AccessDenied for all of
    those, so this reports the real error and lists the likely causes in order
    rather than asserting one.
    """
    msg = str(exc)
    has_external_id = bool(os.getenv("TRACERAI_EXTERNAL_ID"))
    base = f"could not assume TracerAI-ReadOnly in account {account_id}"
    if "AccessDenied" in msg and "AssumeRole" in msg:
        if not has_external_id:
            cause = ("TRACERAI_EXTERNAL_ID is not set, but the role's trust policy "
                     "requires an external id. Set TRACERAI_EXTERNAL_ID to the value "
                     "used when the role was deployed and retry. Do not recreate the "
                     "role; this is almost certainly the cause.")
        else:
            cause = ("AssumeRole was denied. Likely causes, most common first: "
                     "(1) TRACERAI_EXTERNAL_ID does not match the role's trust policy; "
                     "(2) the identity running TracerAI is not granted sts:AssumeRole "
                     "on this role; (3) the TracerAI-ReadOnly role is not deployed in "
                     "this account. Verify 1 and 2 before recreating the role.")
        return f"{base}: {cause} [{msg}]"
    return f"{base}: {msg}"


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


def _mask(account_id: str) -> str:
    """Last-4 display form, for example '...9670'."""
    return "..." + account_id[-4:] if account_id and len(account_id) >= 4 else account_id


def resolve_account(name_or_id: str) -> dict:
    """Resolve an account name (or partial name) to its 12-digit id, so the user
    never has to type the account number.

    Looks the account up in AWS Organizations (id -> name) and matches on name,
    case insensitive: an exact name match wins, otherwise any name that contains
    the text. A 12-digit id passed straight through is validated and, when known,
    named. Each match carries a masked id (last 4) for confirmation.

    Returns:
        query: the input.
        matches: list of {account_id, name, masked}.
        resolved: true when exactly one match (safe to proceed after confirming).
        source: "organizations" or "none".
        note: set when Organizations could not be read, telling the caller to ask
            for the 12-digit id instead.
    """
    q = (name_or_id or "").strip()
    names = _account_names()  # id -> name

    # A full account id: pass through, name it if we can.
    if re.fullmatch(r"\d{12}", q):
        return {"query": q, "resolved": True,
                "source": "organizations" if names else "none",
                "matches": [{"account_id": q, "name": names.get(q), "masked": _mask(q)}]}

    if not names:
        return {"query": q, "resolved": False, "source": "none", "matches": [],
                "note": ("could not read AWS Organizations from here, so names cannot be "
                         "resolved; ask the user for the 12-digit account id")}

    ql = q.lower()
    exact = [(i, n) for i, n in names.items() if (n or "").lower() == ql]
    partial = [(i, n) for i, n in names.items() if ql and ql in (n or "").lower()]
    chosen = exact or partial
    return {
        "query": q,
        "exact": bool(exact),
        "source": "organizations",
        "matches": [{"account_id": i, "name": n, "masked": _mask(i)} for i, n in chosen],
        "resolved": len(chosen) == 1,
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

    # NAT gateways. For overlapping-CIDR designs the private NAT gateway's subnet
    # CIDR is the non-overlapping "outside" range, so include it. Read is wrapped
    # so a missing permission degrades to a note instead of failing discovery.
    subnet_cidr = {s["subnet_id"]: s["cidr"] for s in subnets}
    nat_gateways, nat_note = [], None
    try:
        for page in ec2.get_paginator("describe_nat_gateways").paginate(
                Filter=[{"Name": "vpc-id", "Values": [vpc_id]}]):
            for n in page.get("NatGateways", []):
                nat_gateways.append({
                    "nat_gateway_id": n["NatGatewayId"],
                    "type": n.get("ConnectivityType", "public"),  # public | private
                    "state": n.get("State"),
                    "subnet_id": n.get("SubnetId"),
                    "subnet_cidr": subnet_cidr.get(n.get("SubnetId")),
                    "addresses": [{"private_ip": a.get("PrivateIp"), "public_ip": a.get("PublicIp")}
                                  for a in n.get("NatGatewayAddresses", [])],
                })
    except Exception as e:
        nat_note = f"could not read NAT gateways (needs ec2:DescribeNatGateways): {e}"

    # VPC flow logs (enabled or not, and where they go).
    flow_logs, flow_note = [], None
    try:
        for page in ec2.get_paginator("describe_flow_logs").paginate(
                Filter=[{"Name": "resource-id", "Values": [vpc_id]}]):
            for fl in page.get("FlowLogs", []):
                flow_logs.append({
                    "flow_log_id": fl["FlowLogId"],
                    "status": fl.get("FlowLogStatus"),
                    "traffic_type": fl.get("TrafficType"),
                    "destination_type": fl.get("LogDestinationType"),
                    "destination": fl.get("LogDestination") or fl.get("LogGroupName"),
                })
    except Exception as e:
        flow_note = f"could not read flow logs (needs ec2:DescribeFlowLogs): {e}"

    detail = {
        "name": name, "cidrs": cidrs, "subnets": subnets,
        "route_tables": route_tables, "security_groups": security_groups, "nacls": nacls,
        "nat_gateways": nat_gateways, "flow_logs": flow_logs,
    }
    if nat_note:
        detail["nat_gateways_note"] = nat_note
    if flow_note:
        detail["flow_logs_note"] = flow_note
    return detail


def _tgw_nat_config(ec2, attachment_id: str) -> dict:
    """Read 1:1 NAT rules on a Transit Gateway VPC attachment.

    The attachment NAT feature (launched 2026-10-23) translates MatchSourceCidr
    to NatCidr in both directions. Returns the enabled state and the rules, or a
    note if the call is not permitted or not supported by the endpoint.
    """
    try:
        r = ec2.get_transit_gateway_attachment_nat_configuration(
            TransitGatewayAttachmentId=attachment_id)
        return {
            "enabled": str(r.get("NatGatewaySupport", "")).lower() in ("enable", "enabled"),
            "nat_gateway_support": r.get("NatGatewaySupport"),
            "system_route_support": r.get("NatSystemRouteSupport"),
            "rules": [{"rule_number": x.get("RuleNumber"),
                       "match_source_cidr": x.get("MatchSourceCidr"),
                       "nat_cidr": x.get("NatCidr"),
                       "state": x.get("State")}
                      for x in r.get("NatGatewayRules", [])],
        }
    except Exception as e:
        return {"note": "could not read TGW NAT config "
                        f"(needs ec2:GetTransitGatewayAttachmentNatConfiguration): {e}"}


def discover_network(region: str = None) -> dict:
    """Map the whole network in a region (or several), across accounts.

    region may be a single region, or several comma separated (for example
    "eu-west-1,us-east-1") to validate a cross-region design in one call. Runs in
    the Transit Gateway owner account. Lists every attachment, then for each VPC
    attachment reads that VPC's full detail (CIDRs, subnets, route tables,
    security groups, NACLs, NAT gateways, flow logs) in its owner account,
    assuming the read-only role when the owner is another account and using local
    creds for this account's own VPCs. Each TGW VPC attachment also carries its
    1:1 NAT config. Non-VPC attachments are listed separately. An account with no
    role is reported with a note, not failed.

    Args:
        region: one region, or several comma separated for a cross-region map.

    Returns, for one region: transit_gateways, vpc_attachments, other_attachments
    and cloud_wan. For several regions: by_region keyed by each region.
    """
    if region and "," in region:
        regions = [r.strip() for r in region.split(",") if r.strip()]
        return {"multi_region": True, "regions": regions,
                "by_region": {r: discover_network(r) for r in regions}}
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
            "nat": _tgw_nat_config(ec2, a["TransitGatewayAttachmentId"]),
        }
        try:
            session = get_session(account_id=(None if account_id == me else account_id), region=region)
            entry["vpc"] = _vpc_detail(session, vpc_id, region)
        except Exception as e:
            entry["vpc"] = None
            entry["note"] = _assume_failure_note(account_id, e)
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
                # Per-attachment options (appliance mode, DNS, SG referencing,
                # IPv6) and the attached subnets, from get_vpc_attachment.
                try:
                    va = nm.get_vpc_attachment(
                        AttachmentId=a.get("AttachmentId")).get("VpcAttachment", {})
                    vatt["options"] = va.get("Options")
                    vatt["subnet_arns"] = va.get("SubnetArns")
                    att = va.get("Attachment", {})
                    nat_support = att.get("NatGatewaySupport")
                    if nat_support is not None:
                        vatt["nat"] = {
                            "enabled": str(nat_support).lower() in ("enable", "enabled"),
                            "nat_gateway_support": nat_support,
                            "system_route_support": att.get("NatSystemRouteSupport"),
                        }
                except Exception:
                    pass
                try:
                    session = get_session(
                        account_id=(None if account_id == me else account_id),
                        region=vregion)
                    vatt["vpc"] = _vpc_detail(session, vpc_id, vregion)
                except Exception as e:
                    vatt["vpc"] = None
                    vatt["note"] = _assume_failure_note(account_id, e)
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


def _cidr_contains(cidr: str, ip: str) -> bool:
    """True when ip (an address) falls inside cidr. IPv4/IPv6 safe, never raises."""
    if not cidr or not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _prefix_len(cidr: str) -> int:
    try:
        return ipaddress.ip_network(cidr, strict=False).prefixlen
    except ValueError:
        return -1


def _read_segment_edge_routes(nm, global_network_id, core_network_id, segment_name, edge):
    """Read one segment's route table (RIB) at one edge. Returns a list of routes
    or a dict with an error note. Factored out so it can be called for every edge
    of a segment without duplicating the shape."""
    try:
        resp = nm.get_network_routes(
            GlobalNetworkId=global_network_id,
            RouteTableIdentifier={
                "CoreNetworkSegmentEdge": {
                    "CoreNetworkId": core_network_id,
                    "SegmentName": segment_name,
                    "EdgeLocation": edge,
                }
            })
    except Exception as e:
        return {"error": f"could not read {segment_name} routes at {edge}: {e}"}
    out = []
    for r in resp.get("NetworkRoutes", []):
        out.append({
            "destination": r.get("DestinationCidrBlock"),
            "state": r.get("State"),
            "type": r.get("Type"),
            "targets": [
                {"segment": d.get("SegmentName"), "edge_location": d.get("EdgeLocation"),
                 "resource_type": d.get("ResourceType"), "resource_id": d.get("ResourceId"),
                 "attachment_id": d.get("CoreNetworkAttachmentId")}
                for d in r.get("Destinations", [])
            ],
        })
    return out


def validate_cloud_wan_path(dst_ip: str, segment_name: str = None, core_network_id: str = None,
                            return_ip: str = None, region: str = None) -> dict:
    """Validate how a Cloud WAN segment routes an address, at EVERY edge of the segment.

    This is the check trace_cross_account cannot do by reading one region's RIB: it
    resolves the destination prefix inside the named segment at each edge the segment
    spans, so adding Cloud WAN regions needs no code change. For every edge it reports
    the longest-prefix match for dst_ip (and, when given, return_ip) and the next-hop
    attachment, and FLAGS when a prefix resolves to an inspection or egress attachment
    rather than the VPC/peering attachment that should own it. That misrouting (a spoke
    prefix pointing at the inspection attachment) is the asymmetry class that single-edge
    reads miss.

    Args:
        dst_ip: the destination address to resolve in the segment (the forward path).
        segment_name: the Cloud WAN segment to inspect (e.g. "prod"). When omitted,
            every segment is checked and the matches reported per segment.
        core_network_id: the core network id. When omitted, the single core network is
            used; if there is more than one, the list is returned so the caller can pass one.
        return_ip: optional source address to resolve for the return path, so forward and
            return are validated together (the common asymmetry case).
        region: a region the core network touches, used only to find the global network /
            owner account. The validation itself spans all edges, not just this region.

    Returns core_network_id and, per segment, a list of edge results. Each edge result has
    the matched route for dst_ip (and return_ip), the next-hop attachment, a classification
    (vpc | peering | inspection | egress | blackhole | none), and consistent=False with a
    reason when the match looks wrong (spoke prefix via inspection, blackhole, or no route).
    """
    nm = boto3.client("networkmanager", region_name="us-east-1")

    try:
        core_networks = _nm_paginate(nm.list_core_networks, "CoreNetworks")
    except Exception as e:
        return {"error": f"could not list core networks: {e}"}
    if not core_networks:
        return {"error": "no Cloud WAN core networks found in this account"}

    if core_network_id:
        cn = next((c for c in core_networks if c.get("CoreNetworkId") == core_network_id), None)
        if not cn:
            return {"error": f"core network {core_network_id} not found"}
    elif len(core_networks) == 1:
        cn = core_networks[0]
    else:
        return {"error": "more than one core network; pass core_network_id",
                "core_networks": [c.get("CoreNetworkId") for c in core_networks]}

    core_network_id = cn.get("CoreNetworkId")
    global_network_id = cn.get("GlobalNetworkId")

    # Segments and the edges each spans, from the core network detail.
    try:
        detail = nm.get_core_network(CoreNetworkId=core_network_id)["CoreNetwork"]
    except Exception as e:
        return {"error": f"could not read core network detail: {e}", "core_network_id": core_network_id}
    segments = {s.get("Name"): (s.get("EdgeLocations") or []) for s in detail.get("Segments", [])}
    if segment_name:
        if segment_name not in segments:
            return {"error": f"segment {segment_name} not found",
                    "segments": sorted(segments)}
        targets = {segment_name: segments[segment_name]}
    else:
        targets = segments

    # Which attachments are inspection/egress, so a spoke prefix pointing at one is a leak.
    # An attachment feeding the segment's default route (0.0.0.0/0) is the egress/inspection
    # hop; we learn its id per edge from the default route itself, no hardcoding.
    def classify(route, edge_default_attachment):
        if not route:
            return "none"
        if route.get("state") == "blackhole":
            return "blackhole"
        tgt = (route.get("targets") or [{}])[0]
        att = tgt.get("attachment_id")
        rtype = (tgt.get("resource_type") or "").lower()
        if att and edge_default_attachment and att == edge_default_attachment:
            return "inspection"  # same attachment as the segment default route
        if "peering" in rtype or (tgt.get("resource_type") == "TRANSIT_GATEWAY_PEERING"):
            return "peering"
        if rtype in ("vpc",):
            return "vpc"
        return rtype or "other"

    def best_match(routes, ip):
        best, blen = None, -1
        for r in routes:
            d = r.get("destination")
            if _cidr_contains(d, ip):
                pl = _prefix_len(d)
                if pl > blen:
                    best, blen = r, pl
        return best

    seg_results = {}
    for seg, edges in targets.items():
        edge_results = []
        for edge in edges:
            routes = _read_segment_edge_routes(nm, global_network_id, core_network_id, seg, edge)
            if isinstance(routes, dict) and routes.get("error"):
                edge_results.append({"edge": edge, "error": routes["error"]})
                continue
            default_route = next((r for r in routes
                                  if (r.get("destination") or "") in ("0.0.0.0/0", "::/0")), None)
            default_att = None
            if default_route and default_route.get("targets"):
                default_att = default_route["targets"][0].get("attachment_id")

            fwd = best_match(routes, dst_ip)
            ret = best_match(routes, return_ip) if return_ip else None

            # Relevance: a segment/edge that carries neither address is simply not this
            # flow's segment (expected for unrelated segments in an all-segments sweep).
            # Do not judge it, so the sweep does not flood with false "no route" problems.
            if fwd is None and ret is None:
                edge_results.append({"edge": edge, "relevant": False})
                continue

            fwd_class = classify(fwd, default_att)
            res = {"edge": edge, "relevant": True,
                   "forward": {"dst_ip": dst_ip, "match": fwd, "classification": fwd_class}}
            consistent, reason = True, None
            if fwd is None:
                # Return matched here but forward did not: reverse-only presence is itself
                # an asymmetry worth surfacing on a relevant segment.
                consistent, reason = False, (
                    f"segment {seg} at {edge} has a route for the return address {return_ip} but "
                    f"none for the forward address {dst_ip} (asymmetric)")
            elif fwd_class == "blackhole":
                consistent, reason = False, f"{dst_ip} is blackholed in segment {seg} at {edge}"
            elif fwd_class == "inspection":
                consistent, reason = False, (
                    f"{dst_ip} in segment {seg} at {edge} resolves to the inspection/egress "
                    f"attachment ({(fwd.get('targets') or [{}])[0].get('attachment_id')}); a spoke "
                    "prefix should reach its VPC or the TGW peering, not inspection. This is the "
                    "prod-to-prod-via-inspection leak class.")

            if return_ip:
                ret_class = classify(ret, default_att)
                res["return"] = {"return_ip": return_ip, "match": ret, "classification": ret_class}
                if ret is None:
                    consistent, reason = False, (reason or
                        f"segment {seg} at {edge} routes the forward address {dst_ip} but has no "
                        f"return route for {return_ip} (asymmetric: traffic goes but cannot return)")
                elif ret_class == "blackhole":
                    consistent, reason = False, (reason or
                        f"{return_ip} is blackholed in segment {seg} at {edge}")
                elif ret_class == "inspection":
                    consistent, reason = False, (reason or
                        f"return address {return_ip} in segment {seg} at {edge} resolves to the "
                        "inspection/egress attachment; the return path is leaking into inspection.")

            res["consistent"] = consistent
            if reason:
                res["reason"] = reason
            edge_results.append(res)
        seg_results[seg] = edge_results

    all_edges = [e for edges in seg_results.values() for e in edges if "consistent" in e]
    inconsistent = [e for e in all_edges if not e["consistent"]]
    return {
        "core_network_id": core_network_id,
        "global_network_id": global_network_id,
        "dst_ip": dst_ip, "return_ip": return_ip,
        "segments_checked": sorted(targets),
        "segment_results": seg_results,
        "consistent": not inconsistent,
        "problems": [{"segment": s, **e}
                     for s, edges in seg_results.items() for e in edges
                     if "consistent" in e and not e["consistent"]],
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
                "error": _assume_failure_note(account_id, e)}
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
                "error": _assume_failure_note(account_id, e)}

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
