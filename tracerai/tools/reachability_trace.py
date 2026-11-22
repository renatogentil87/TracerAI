"""Cross-account reachability tracing (config based).

Walks the path between a source and a destination that live in different AWS
accounts, using read-only describe calls only. It does not run EC2 Reachability
Analyzer (which cannot see another account's route tables) and it changes
nothing.

The walk, forward then return:
  1. source security group egress allows the destination and port
  2. source subnet NACL egress allows it
  3. source VPC route table: which target owns the destination prefix
  4. if it leaves via a Transit Gateway, the source attachment's associated TGW
     route table (read in the TGW owner account) has a route to the destination
  5. if that route points at an inspection VPC rather than the destination,
     flag it: everything else is checked, but the firewall must be verified by
     hand
  6. destination security group ingress and subnet NACL ingress allow the source
  7. return path: the destination side routes back to the source, including the
     TGW return route, and the stateless NACLs allow the ephemeral return

It reports the first layer that blocks the flow, or says the path looks open.
Anything it cannot read (a role it cannot assume, a prefix list it cannot
expand) is reported as a coverage gap, not a false "blocked".

    python tracerai/tools/reachability_trace.py
"""

import ipaddress

import boto3

from tracerai.aws_session import get_session
from tracerai.tools.cross_account import _flatten_sg_rule, _assume_failure_note, _tgw_nat_config


def _norm(account_id, me):
    """Use local credentials when the target account is the one we run in."""
    return None if (not account_id or account_id == me) else account_id

EPHEMERAL = (1024, 65535)
_CANON = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmpv6",
          "tcp": "tcp", "udp": "udp", "icmp": "icmp", "icmpv6": "icmpv6", "-1": "-1"}


def _canon(proto) -> str:
    """Normalize a protocol to a name. Security groups report names
    (tcp/udp/icmp/-1), NACLs report numbers (6/17/1/-1); accept either."""
    return _CANON.get(str(proto).lower(), str(proto).lower())


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def _ip_in(ip: str, cidr: str) -> bool:
    if not cidr or ":" in cidr or not _is_ipv4(ip):
        return False
    try:
        return ipaddress.IPv4Address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _resolve(session, identifier: str, region: str) -> list:
    """Resolve a name, instance id, private IP, or ARN to candidate instances."""
    ec2 = session.client("ec2", region_name=region)
    ident = identifier.strip()
    if ident.startswith("arn:"):
        ident = ident.split("/")[-1]

    kwargs = {}
    if ident.startswith("i-"):
        kwargs["InstanceIds"] = [ident]
    elif _is_ipv4(ident):
        kwargs["Filters"] = [{"Name": "private-ip-address", "Values": [ident]}]
    else:
        kwargs["Filters"] = [{"Name": "tag:Name", "Values": [f"*{ident}*"]}]

    cands = []
    for res in ec2.describe_instances(**kwargs).get("Reservations", []):
        for inst in res.get("Instances", []):
            name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), None)
            cands.append({
                "instance_id": inst["InstanceId"],
                "name": name,
                "state": inst.get("State", {}).get("Name"),
                "private_ip": inst.get("PrivateIpAddress"),
                "vpc_id": inst.get("VpcId"),
                "subnet_id": inst.get("SubnetId"),
                "az": inst.get("Placement", {}).get("AvailabilityZone"),
                "security_groups": [g["GroupId"] for g in inst.get("SecurityGroups", [])],
            })
    return cands


def resolve_endpoint(identifier: str, account_id: str = None, region: str = None) -> dict:
    """Resolve an endpoint in an account to its instances and network context.

    identifier may be a Name tag (partial, case insensitive), an instance id, a
    private IP, or an instance ARN. With account_id the read-only role is assumed
    in that account; without it the current account is used.
    """
    try:
        session = get_session(account_id=_norm(account_id, boto3.client("sts").get_caller_identity()["Account"]), region=region)
    except Exception as e:
        return {"account_id": account_id, "identifier": identifier,
                "error": _assume_failure_note(account_id, e)}
    try:
        candidates = _resolve(session, identifier, region)
    except Exception as e:
        return {"account_id": account_id, "identifier": identifier, "error": str(e)}
    return {"account_id": account_id, "region": region, "identifier": identifier,
            "match_count": len(candidates), "candidates": candidates}


def _gather(session, region: str, instance_id: str) -> dict:
    """Collect the network context of one instance: IP, VPC, subnet, SGs, the
    subnet's route table, and the subnet's NACL (with port ranges)."""
    ec2 = session.client("ec2", region_name=region)
    inst = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    vpc_id, subnet_id = inst["VpcId"], inst["SubnetId"]
    ctx = {
        "instance_id": instance_id,
        "private_ip": inst.get("PrivateIpAddress"),
        "vpc_id": vpc_id,
        "subnet_id": subnet_id,
        "sg_ids": [g["GroupId"] for g in inst.get("SecurityGroups", [])],
    }

    groups = ec2.describe_security_groups(GroupIds=ctx["sg_ids"])["SecurityGroups"] if ctx["sg_ids"] else []
    ctx["sg_inbound"] = [_flatten_sg_rule(r) for g in groups for r in g.get("IpPermissions", [])]
    ctx["sg_outbound"] = [_flatten_sg_rule(r) for g in groups for r in g.get("IpPermissionsEgress", [])]

    # Route table associated with the subnet, else the VPC main table.
    rts = ec2.describe_route_tables(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]).get("RouteTables", [])
    if not rts:
        rts = ec2.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                     {"Name": "association.main", "Values": ["true"]}]).get("RouteTables", [])
    ctx["route_table"] = rts[0] if rts else None

    nacls = ec2.describe_network_acls(
        Filters=[{"Name": "association.subnet-id", "Values": [subnet_id]}]).get("NetworkAcls", [])
    ctx["nacl"] = nacls[0] if nacls else None
    return ctx


def _sg_allows(rules: list, ip: str, port: int, proto: str):
    """Does any SG rule allow ip:port by CIDR or prefix list? Returns
    (True, cidr) on a CIDR match, (None, "sg/pl") when only group or prefix-list
    sources exist (cannot be resolved cross-account), or (False, None)."""
    saw_unresolvable = False
    want = _canon(proto)
    for r in rules:
        rp = _canon(r.get("protocol", "-1"))
        if rp != "-1" and rp != want:
            continue
        # Port range applies to TCP/UDP only; for ICMP the from/to are type/code.
        if rp != "-1" and want in ("tcp", "udp"):
            fp, tp = r.get("from_port"), r.get("to_port")
            if fp is not None and tp is not None and not (fp <= port <= tp):
                continue
        for src in r.get("sources", []):
            if "/" in src and ":" not in src:
                if _ip_in(ip, src):
                    return True, src
            else:
                saw_unresolvable = True
    return (None, "security-group or prefix-list source") if saw_unresolvable else (False, None)


def _nacl_allows(nacl: dict, egress: bool, ip: str, port: int, proto: str):
    """Evaluate a NACL in rule-number order; first match wins. Returns
    (True/False, rule_number). No NACL means the default allow-all."""
    if not nacl:
        return True, None
    want = _canon(proto)
    for e in sorted(nacl.get("Entries", []), key=lambda x: x["RuleNumber"]):
        if bool(e.get("Egress")) != egress:
            continue
        ep = _canon(e.get("Protocol"))
        if ep != "-1" and ep != want:
            continue
        cidr = e.get("CidrBlock")
        if not cidr or ":" in cidr or not _ip_in(ip, cidr):
            continue
        pr = e.get("PortRange")
        if want in ("tcp", "udp") and pr and not (pr.get("From", 0) <= port <= pr.get("To", 65535)):
            continue
        return e.get("RuleAction") == "allow", e.get("RuleNumber")
    return False, None  # fell through the implicit deny


def _match_route(routes: list, ip: str):
    """Longest-prefix match over a list of routes (each a dict with a cidr)."""
    best, best_len = None, -1
    for r in routes:
        cidr = r.get("cidr")
        if _ip_in(ip, cidr or ""):
            plen = int(cidr.split("/")[1])
            if plen > best_len:
                best, best_len = r, plen
    return best


def _route_target(route: dict):
    """Classify a VPC route's target as (kind, id)."""
    if route.get("TransitGatewayId"):
        return "tgw", route["TransitGatewayId"]
    if route.get("NatGatewayId"):
        return "nat", route["NatGatewayId"]
    if route.get("VpcPeeringConnectionId"):
        return "peering", route["VpcPeeringConnectionId"]
    if route.get("CoreNetworkArn"):
        return "core_network", route["CoreNetworkArn"]
    if route.get("NetworkInterfaceId"):
        return "eni", route["NetworkInterfaceId"]
    gw = route.get("GatewayId")
    if gw == "local":
        return "local", "local"
    if gw and gw.startswith("igw-"):
        return "igw", gw
    if gw and gw.startswith("vpce-"):
        return "endpoint", gw
    if gw:
        return "gateway", gw
    return "unknown", None


def _vpc_routes(route_table: dict) -> list:
    out = []
    for r in (route_table or {}).get("Routes", []):
        out.append({"cidr": r.get("DestinationCidrBlock"),
                    "target": _route_target(r), "state": r.get("State")})
    return out


def _tgw_assoc_and_lookup(tgw_session, region, vpc_id, dst_ip):
    """In the TGW owner account, find the VPC attachment, its associated route
    table, and the route that covers dst_ip. Returns a dict describing it."""
    ec2 = tgw_session.client("ec2", region_name=region)
    atts = ec2.describe_transit_gateway_attachments(Filters=[
        {"Name": "resource-id", "Values": [vpc_id]},
        {"Name": "resource-type", "Values": ["vpc"]}]).get("TransitGatewayAttachments", [])
    if not atts:
        return {"error": f"no TGW VPC attachment found for {vpc_id} in the TGW account"}
    att = atts[0]
    rt_id = (att.get("Association") or {}).get("TransitGatewayRouteTableId")
    if not rt_id:
        return {"attachment_id": att["TransitGatewayAttachmentId"],
                "error": "attachment is not associated with a TGW route table"}
    resp = ec2.search_transit_gateway_routes(
        TransitGatewayRouteTableId=rt_id,
        Filters=[{"Name": "state", "Values": ["active", "blackhole"]}])
    routes = []
    for r in resp.get("Routes", []):
        tgt = r.get("TransitGatewayAttachments", [{}])[0] if r.get("TransitGatewayAttachments") else {}
        routes.append({"cidr": r.get("DestinationCidrBlock"), "state": r.get("State"),
                       "resource_id": tgt.get("ResourceId"), "resource_type": tgt.get("ResourceType"),
                       "attachment_id": tgt.get("TransitGatewayAttachmentId")})
    match = _match_route(routes, dst_ip)
    return {"attachment_id": att["TransitGatewayAttachmentId"], "route_table_id": rt_id, "match": match}


def _tgw_owner(session, region, tgw_id):
    """The account that owns a Transit Gateway (visible even when it is shared)."""
    try:
        tgws = session.client("ec2", region_name=region).describe_transit_gateways(
            TransitGatewayIds=[tgw_id]).get("TransitGateways", [])
        return tgws[0].get("OwnerId") if tgws else None
    except Exception:
        return None


def _nat_translate(ip, match_cidr, nat_cidr):
    """Map ip (inside match_cidr) to the same host offset inside nat_cidr.

    1:1 NAT preserves the host address, so 10.100.0.5 in 10.100.0.0/24 with a NAT
    CIDR of 172.30.0.0/24 becomes 172.30.0.5.
    """
    try:
        m = ipaddress.ip_network(match_cidr, strict=False)
        n = ipaddress.ip_network(nat_cidr, strict=False)
        a = ipaddress.IPv4Address(ip)
        if a not in m:
            return None
        return str(ipaddress.IPv4Address(int(n.network_address) + (int(a) - int(m.network_address))))
    except Exception:
        return None


def _endpoint_nat(session, region, vpc_id, route_table, me, account_id, tgw_account_id):
    """Best-effort 1:1 NAT for a VPC's attachment.

    For a Transit Gateway attachment the rule is read directly. For a Cloud WAN
    attachment the rule CIDRs are not exposed by the API, so this flags it as
    unreadable and the NAT CIDR must be confirmed from the segment route tables.
    Returns a dict or None when the VPC's attachment has no NAT.
    """
    try:
        ec2 = session.client("ec2", region_name=region)
        atts = ec2.describe_transit_gateway_attachments(Filters=[
            {"Name": "resource-id", "Values": [vpc_id]},
            {"Name": "resource-type", "Values": ["vpc"]}]).get("TransitGatewayAttachments", [])
        if atts:
            tgw_id = atts[0].get("TransitGatewayId")
            owner = tgw_account_id or _tgw_owner(session, region, tgw_id) or account_id
            osess = get_session(account_id=_norm(owner, me), region=region)
            cfg = _tgw_nat_config(osess.client("ec2", region_name=region),
                                  atts[0]["TransitGatewayAttachmentId"])
            if cfg.get("rules"):
                return {"backbone": "transit gateway", "enabled": cfg.get("enabled"),
                        "rule": cfg["rules"][0]}
            if cfg.get("enabled"):
                return {"backbone": "transit gateway", "enabled": True}
    except Exception:
        pass
    # Cloud WAN fallback: the VPC routes to a core network.
    for r in _vpc_routes(route_table):
        if r["target"][0] == "core_network":
            return {"backbone": "Cloud WAN", "unreadable": True}
    return None


def trace_cross_account(src_instance_id: str, dst: str, port: int, protocol: str = "tcp",
                        region: str = None, src_account_id: str = None,
                        dst_account_id: str = None, tgw_account_id: str = None,
                        src_region: str = None, dst_region: str = None) -> dict:
    """Trace reachability from a source to a destination across accounts and regions.

    dst may be a destination instance id (preferred) or a private IP. For a
    cross-region path set src_region and dst_region; otherwise region applies to
    both. The walk is 1:1 NAT aware: if an endpoint's attachment translates its
    address, the walk uses the translated (outside) address, because the source
    must target the destination's NAT address and the destination sees the
    source's NAT address. tgw_account_id (the hub) is resolved from the TGW's
    OwnerId when omitted.
    """
    findings = []

    def add(step, result, detail):
        findings.append({"step": step, "result": result, "detail": detail})

    me = boto3.client("sts").get_caller_identity()["Account"]
    sreg = src_region or region
    dreg = dst_region or region or sreg
    if not sreg:
        return {"error": "no region given (set region, or src_region and dst_region)",
                "findings": findings}
    cross_region = sreg != dreg

    try:
        src_session = get_session(account_id=_norm(src_account_id, me), region=sreg)
    except Exception as e:
        return {"error": _assume_failure_note(src_account_id, e), "findings": findings}
    dst_session = None
    if dst_account_id:
        try:
            dst_session = get_session(account_id=_norm(dst_account_id, me), region=dreg)
        except Exception as e:
            add("destination account", "unknown", _assume_failure_note(dst_account_id, e))

    src = _gather(src_session, sreg, src_instance_id)
    src_ip = src["private_ip"]
    dst_ctx, dst_ip = None, None
    if dst.startswith("i-") and dst_session is not None:
        dst_ctx = _gather(dst_session, dreg, dst)
        dst_ip = dst_ctx["private_ip"]
    elif _is_ipv4(dst):
        dst_ip = dst
    if not dst_ip:
        add("destination", "unknown",
            "could not determine the destination IP (give a destination instance id with its "
            "account, or a private IP)")
        return {"src_ip": src_ip, "dst": dst, "port": port, "protocol": protocol, "findings": findings}

    # 1:1 NAT translation. effective_dst is what the source must target; effective_src
    # is what the destination sees as the source.
    effective_src, effective_dst = src_ip, dst_ip
    src_nat = _endpoint_nat(src_session, sreg, src["vpc_id"], src.get("route_table"),
                            me, src_account_id, tgw_account_id)
    if src_nat and src_nat.get("rule"):
        t = _nat_translate(src_ip, src_nat["rule"]["match_source_cidr"], src_nat["rule"]["nat_cidr"])
        if t:
            effective_src = t
            add("source NAT", "info",
                f"source {src_ip} is translated to {t} by the {src_nat['backbone']} NAT rule "
                f"{src_nat['rule'].get('rule_number')} ({src_nat['rule']['match_source_cidr']} -> "
                f"{src_nat['rule']['nat_cidr']}); the destination sees {t}")
    elif src_nat and src_nat.get("unreadable"):
        add("source NAT", "unknown",
            f"the source is on {src_nat['backbone']} and may translate its address, but the API "
            "does not expose the rule CIDRs; confirm the NAT CIDR from the segment route tables")
    if dst_ctx:
        dst_nat = _endpoint_nat(dst_session or src_session, dreg, dst_ctx["vpc_id"],
                                dst_ctx.get("route_table"), me, dst_account_id, tgw_account_id)
        if dst_nat and dst_nat.get("rule"):
            t = _nat_translate(dst_ip, dst_nat["rule"]["match_source_cidr"], dst_nat["rule"]["nat_cidr"])
            if t:
                effective_dst = t
                add("destination NAT", "info",
                    f"destination {dst_ip} is reached at its NAT address {t} "
                    f"({dst_nat['backbone']} rule {dst_nat['rule'].get('rule_number')}: "
                    f"{dst_nat['rule']['match_source_cidr']} -> {dst_nat['rule']['nat_cidr']}); "
                    f"the source must target {t}, not {dst_ip}")
        elif dst_nat and dst_nat.get("unreadable"):
            add("destination NAT", "unknown",
                f"the destination is on {dst_nat['backbone']} with NAT; the source must target the "
                "destination's NAT CIDR, which the API does not expose. Find it in the segment "
                "route tables and confirm the source routes to it")

    # 1. Source SG egress (to the address the source actually targets).
    ok, why = _sg_allows(src["sg_outbound"], effective_dst, port, protocol)
    if ok is True:
        add("source security group egress", "pass",
            f"egress allows {proto_port(protocol, port)} to {effective_dst} via {why}")
    elif ok is None:
        add("source security group egress", "unknown",
            f"egress only references {why}; could not confirm {effective_dst} by CIDR")
    else:
        add("source security group egress", "fail",
            f"no egress rule allows {proto_port(protocol, port)} to {effective_dst}")

    # 2. Source NACL egress.
    ok, rule = _nacl_allows(src.get("nacl"), True, effective_dst, port, protocol)
    add("source NACL egress", "pass" if ok else "fail",
        f"{'allowed' if ok else 'denied'} by NACL {src.get('nacl', {}).get('NetworkAclId')}"
        + (f" rule {rule}" if rule else ""))

    # 3. Source VPC route table (to the effective destination).
    routes = _vpc_routes(src.get("route_table"))
    match = _match_route(routes, effective_dst)
    via_tgw, tgw_id = False, None
    if not match:
        add("source route table", "fail",
            f"no route to {effective_dst} in {src.get('route_table', {}).get('RouteTableId')}")
    else:
        kind, tid = match["target"]
        add("source route table", "pass",
            f"{effective_dst} routes via {kind} {tid} (match {match['cidr']})")
        via_tgw = kind == "tgw"
        if via_tgw:
            tgw_id = tid

    # 4 + 5. Transit Gateway route table (source side) and inspection detection.
    tgw_acct = (tgw_account_id or _tgw_owner(src_session, sreg, tgw_id)
                or dst_account_id or src_account_id) if via_tgw else None
    inspection = None
    if via_tgw:
        try:
            tgw_session = get_session(account_id=_norm(tgw_acct, me), region=sreg)
            tgw = _tgw_assoc_and_lookup(tgw_session, sreg, src["vpc_id"], effective_dst)
        except Exception as e:
            tgw = {"error": _assume_failure_note(tgw_acct, e)}
        if tgw.get("error"):
            add("transit gateway route table", "unknown", tgw["error"])
        elif not tgw.get("match") or tgw["match"].get("state") == "blackhole":
            state = (tgw.get("match") or {}).get("state")
            add("transit gateway route table", "fail",
                f"TGW route table {tgw.get('route_table_id')} has "
                + ("a blackhole route" if state == "blackhole" else "no route")
                + f" for {effective_dst}")
        else:
            m = tgw["match"]
            dst_vpc = dst_ctx["vpc_id"] if dst_ctx else None
            add("transit gateway route table", "pass",
                f"TGW route table {tgw['route_table_id']} sends {effective_dst} to "
                f"{m.get('resource_type')} {m.get('resource_id')} (match {m.get('cidr')})")
            if m.get("resource_type") == "vpc" and dst_vpc and m.get("resource_id") != dst_vpc:
                inspection = m.get("resource_id")

    # Cross-region / cross-backbone leg that this walk cannot follow end to end.
    if cross_region:
        add("inter-region leg", "unknown",
            f"source is in {sreg} and destination in {dreg}. This walk checks each side in its "
            "own region but does not follow the inter-region Transit Gateway peering or Cloud WAN "
            "core-network hop between them; confirm the segment or peering routes carry "
            f"{effective_dst} from {sreg} to {dreg} and {effective_src} back")

    # 6. Destination SG + NACL ingress (from the source address the destination sees).
    if dst_ctx:
        ok, why = _sg_allows(dst_ctx["sg_inbound"], effective_src, port, protocol)
        if ok is True:
            add("destination security group ingress", "pass",
                f"ingress allows {proto_port(protocol, port)} from {effective_src} via {why}")
        elif ok is None:
            add("destination security group ingress", "unknown",
                f"ingress only references {why}; cross-account sources must be a CIDR")
        else:
            add("destination security group ingress", "fail",
                f"no ingress rule allows {proto_port(protocol, port)} from {effective_src}")
        ok, rule = _nacl_allows(dst_ctx.get("nacl"), False, effective_src, port, protocol)
        add("destination NACL ingress", "pass" if ok else "fail",
            f"{'allowed' if ok else 'denied'} by NACL {dst_ctx.get('nacl', {}).get('NetworkAclId')}"
            + (f" rule {rule}" if rule else ""))
    else:
        add("destination security group ingress", "unknown",
            "destination instance/account not provided, so its inbound rules were not checked")

    # 7. Return path: destination-side TGW route back to the effective source, and NACLs.
    if dst_ctx:
        dmatch = _match_route(_vpc_routes(dst_ctx.get("route_table")), effective_src)
        if dmatch and dmatch["target"][0] == "tgw":
            back_tgw_id = dmatch["target"][1]
            back_acct = (tgw_account_id or _tgw_owner(dst_session or src_session, dreg, back_tgw_id)
                         or dst_account_id or src_account_id)
            try:
                back_session = get_session(account_id=_norm(back_acct, me), region=dreg)
                back = _tgw_assoc_and_lookup(back_session, dreg, dst_ctx["vpc_id"], effective_src)
            except Exception as e:
                back = {"error": _assume_failure_note(back_acct, e)}
            if back.get("error"):
                add("return path (TGW)", "unknown", back["error"])
            elif not back.get("match") or back["match"].get("state") == "blackhole":
                add("return path (TGW)", "fail",
                    f"destination's TGW route table {back.get('route_table_id')} has no return "
                    f"route to {effective_src} (asymmetric routing: traffic goes out but not back)")
            else:
                add("return path (TGW)", "pass",
                    f"return route to {effective_src} present via {back['match'].get('cidr')}")
        ok, rule = _nacl_allows(dst_ctx.get("nacl"), True, effective_src, EPHEMERAL[0], protocol)
        if not ok:
            add("return path (NACL)", "fail",
                f"destination NACL does not allow the ephemeral return to {effective_src}")
        ok, rule = _nacl_allows(src.get("nacl"), False, effective_dst, EPHEMERAL[0], protocol)
        if not ok:
            add("return path (NACL)", "fail",
                f"source NACL does not allow the ephemeral return from {effective_dst}")

    # Firewall / inspection note.
    if inspection:
        add("inspection / firewall", "info",
            f"traffic is routed through VPC {inspection} (likely a firewall or inspection VPC) "
            "before reaching the destination. This tool does not read firewall rules: everything "
            "around it checks out, so if connectivity still fails, verify the firewall policy "
            f"allows {proto_port(protocol, port)} from {effective_src} to {effective_dst}.")

    fails = [f for f in findings if f["result"] == "fail"]
    unknowns = [f for f in findings if f["result"] == "unknown"]
    if fails:
        verdict = f"blocked at: {fails[0]['step']}"
    elif unknowns:
        verdict = "no blocker found in what could be read; some layers were not readable (see unknowns)"
    else:
        verdict = "path looks open (config based; a live packet may still differ)"

    return {"src_ip": src_ip, "dst": dst, "dst_ip": dst_ip,
            "effective_src": effective_src, "effective_dst": effective_dst,
            "src_region": sreg, "dst_region": dreg,
            "port": port, "protocol": protocol,
            "findings": findings, "blocked": bool(fails), "verdict": verdict}


def proto_port(protocol: str, port: int) -> str:
    if _canon(protocol) in ("icmp", "icmpv6", "-1"):
        return _canon(protocol)
    return f"{protocol}/{port}"


if __name__ == "__main__":
    import json
    print(json.dumps(resolve_endpoint("prod", account_id=None, region="ca-central-1"), indent=2))
