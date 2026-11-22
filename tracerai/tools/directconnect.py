"""Direct Connect health and resilience.

Two read-only capabilities:

- check_direct_connect: the state of each connection (dedicated or hosted), each
  virtual interface, each BGP peer (up or down), and the prefixes the Direct
  Connect gateway advertises toward on-premises.
- recommend_dx_resilience: the current resilience posture and what to add to
  reach the 99.9% or 99.99% SLA, following the AWS Direct Connect Resiliency
  Toolkit.

The Direct Connect API does not expose the BGP routes received from on-premises;
those appear in the attached VGW or Transit Gateway route table, which the
discovery and route-table tools read.

    python tracerai/tools/directconnect.py
"""

import boto3

from tracerai.aws_session import get_session

# AWS Direct Connect Resiliency Toolkit models and their SLAs.
# https://docs.aws.amazon.com/directconnect/latest/UserGuide/resiliency_toolkit.html
# https://docs.aws.amazon.com/directconnect/latest/UserGuide/connection_options.html
SLA_HIGH = "99.9%"
SLA_MAX = "99.99%"
DOC_RESILIENCY = "https://docs.aws.amazon.com/directconnect/latest/UserGuide/resiliency_toolkit.html"


def _norm(account_id, me):
    return None if (not account_id or account_id == me) else account_id


def _dc_client(account_id, region):
    me = boto3.client("sts").get_caller_identity()["Account"]
    session = get_session(account_id=_norm(account_id, me), region=region)
    return session.client("directconnect", region_name=region)


def _connection_view(c: dict) -> dict:
    return {
        "connection_id": c["connectionId"],
        "name": c.get("connectionName"),
        "state": c.get("connectionState"),
        "healthy": c.get("connectionState") == "available",
        "location": c.get("location"),
        "bandwidth": c.get("bandwidth"),
        # A hosted connection is provisioned by a partner on their port; a
        # dedicated connection is a port you own.
        "type": "hosted" if c.get("partnerName") else "dedicated",
        "partner": c.get("partnerName"),
        "lag_id": c.get("lagId"),
        "device": c.get("awsDeviceV2"),
        "macsec_capable": c.get("macSecCapable"),
    }


def check_direct_connect(connection_id: str = None, region: str = None,
                         account_id: str = None) -> dict:
    """Report the health of Direct Connect connections, VIFs and BGP peers.

    With connection_id the result is scoped to that connection; otherwise every
    connection in the region is checked. account_id reads another account through
    the read-only role. Needs directconnect:Describe* in the account read.
    """
    if not region:
        return {"needs_region": True}
    try:
        dc = _dc_client(account_id, region)
    except Exception as e:
        return {"region": region, "account_id": account_id, "error": str(e)}

    conns = dc.describe_connections().get("connections", [])
    if connection_id:
        conns = [c for c in conns if c["connectionId"] == connection_id]
    connections = [_connection_view(c) for c in conns]

    vif_kwargs = {"connectionId": connection_id} if connection_id else {}
    vifs = dc.describe_virtual_interfaces(**vif_kwargs).get("virtualInterfaces", [])

    virtual_interfaces, dxgw_ids = [], set()
    for v in vifs:
        peers = [{
            "address_family": p.get("addressFamily"),
            "bgp_status": p.get("bgpStatus"),        # up | down | unknown
            "peer_state": p.get("bgpPeerState"),     # available | pending | ...
            "up": p.get("bgpStatus") == "up",
            "asn": p.get("asn"),
            "customer_address": p.get("customerAddress"),
            "device": p.get("awsDeviceV2"),
        } for p in v.get("bgpPeers", [])]
        if v.get("directConnectGatewayId"):
            dxgw_ids.add(v["directConnectGatewayId"])
        virtual_interfaces.append({
            "vif_id": v["virtualInterfaceId"],
            "type": v.get("virtualInterfaceType"),   # private | public | transit
            "state": v.get("virtualInterfaceState"),
            "healthy": v.get("virtualInterfaceState") == "available",
            "vlan": v.get("vlan"),
            "connection_id": v.get("connectionId"),
            "dx_gateway_id": v.get("directConnectGatewayId"),
            "bgp_peers": peers,
            "bgp_all_up": bool(peers) and all(p["up"] for p in peers),
        })

    # Prefixes the DX gateway advertises toward on-premises.
    dx_gateways = []
    for gw_id in sorted(dxgw_ids):
        try:
            assoc = dc.describe_direct_connect_gateway_associations(
                directConnectGatewayId=gw_id).get("directConnectGatewayAssociations", [])
        except Exception as e:
            dx_gateways.append({"dx_gateway_id": gw_id, "note": f"could not read associations: {e}"})
            continue
        dx_gateways.append({
            "dx_gateway_id": gw_id,
            "associations": [{
                "associated_gateway_id": (a.get("associatedGateway") or {}).get("id"),
                "associated_gateway_type": (a.get("associatedGateway") or {}).get("type"),
                "state": a.get("associationState"),
                "advertised_prefixes": [p.get("cidr") for p in a.get("allowedPrefixesToDirectConnectGateway", [])],
            } for a in assoc],
        })

    issues = []
    for c in connections:
        if not c["healthy"]:
            issues.append(f"connection {c['connection_id']} is {c['state']}")
    for v in virtual_interfaces:
        if not v["healthy"]:
            issues.append(f"VIF {v['vif_id']} is {v['state']}")
        for p in v["bgp_peers"]:
            if not p["up"]:
                issues.append(f"VIF {v['vif_id']} BGP {p['address_family']} is {p['bgp_status']} "
                              f"(peer state {p['peer_state']})")

    return {
        "region": region, "account_id": account_id,
        "connections": connections,
        "virtual_interfaces": virtual_interfaces,
        "dx_gateways": dx_gateways,
        "issues": issues,
        "healthy": not issues,
        "received_routes_note": ("the Direct Connect API does not return routes received from "
                                 "on-premises; read the attached VGW or Transit Gateway route table "
                                 "to see the learned prefixes"),
    }


def _assess(connections: list) -> dict:
    """Classify the resilience posture from a list of connection views."""
    active = [c for c in connections if c.get("state") not in ("deleted", "deleting", "rejected")]
    per_location = {}
    for c in active:
        per_location.setdefault(c.get("location"), []).append(c)
    locations = sorted(k for k in per_location if k)
    devices = sorted({c.get("device") for c in active if c.get("device")})
    n, n_locs = len(active), len(locations)
    redundant_each_location = bool(per_location) and all(len(v) >= 2 for v in per_location.values())

    meets_high = n >= 2 and n_locs >= 2
    meets_max = n_locs >= 2 and redundant_each_location and len(devices) >= 2

    if n == 0:
        level = "no Direct Connect"
    elif n == 1:
        level = "Development (single connection, no SLA)"
    elif meets_max:
        level = f"Maximum Resiliency ({SLA_MAX})"
    elif meets_high:
        level = f"High Resiliency ({SLA_HIGH})"
    else:
        level = "redundant but single location (device redundancy only, no location diversity)"

    return {"connection_count": n, "locations": locations, "location_count": n_locs,
            "devices": devices, "meets_99_9": meets_high, "meets_99_99": meets_max,
            "level": level}


def recommend_dx_resilience(region: str = None, account_id: str = None) -> dict:
    """Assess Direct Connect resilience and recommend how to reach 99.9% or 99.99%.

    Follows the AWS Direct Connect Resiliency Toolkit: High Resiliency (99.9%) is
    two connections in two different DX locations; Maximum Resiliency (99.99%) is
    separate connections on distinct devices in more than one location. Reads the
    current connections and, when a location must be added, suggests DX locations
    not already in use.
    """
    if not region:
        return {"needs_region": True}
    try:
        dc = _dc_client(account_id, region)
    except Exception as e:
        return {"region": region, "account_id": account_id, "error": str(e)}

    conns = [_connection_view(c) for c in dc.describe_connections().get("connections", [])]
    assessment = _assess(conns)

    notes = []
    if assessment["connection_count"] == 0:
        try:
            vifs = dc.describe_virtual_interfaces().get("virtualInterfaces", [])
        except Exception:
            vifs = []
        if vifs:
            notes.append(f"{len(vifs)} virtual interface(s) exist but no Direct Connect connection "
                         "is visible in this account, so the physical connection is hosted or owned "
                         "by another account. Resilience is assessed on the connections visible here; "
                         "check the owning account for the real posture.")

    used = set(assessment["locations"])
    try:
        all_locs = dc.describe_locations().get("locations", [])
    except Exception:
        all_locs = []
    other_locations = [{"code": l.get("locationCode"), "name": l.get("locationName")}
                       for l in all_locs if l.get("locationCode") not in used][:5]

    # Recommendations keyed to each SLA target, stated against the current posture.
    rec = {}
    if assessment["meets_99_9"]:
        rec[SLA_HIGH] = "Already met: you have connections in at least two DX locations."
    else:
        rec[SLA_HIGH] = ("Add a connection in a DIFFERENT DX location from the one(s) in use. "
                         "High Resiliency is two connections, each in its own DX location.")
    if assessment["meets_99_99"]:
        rec[SLA_MAX] = "Already met: redundant connections on distinct devices across more than one location."
    else:
        rec[SLA_MAX] = ("Diversify to at least two DX locations and put redundant connections on "
                        "distinct devices in each, terminating on separate on-premises devices and "
                        "locations. Maximum Resiliency needs that full separation.")

    return {
        "region": region, "account_id": account_id,
        "current": assessment,
        "recommendations": rec,
        "suggested_additional_locations": other_locations,
        "reference": DOC_RESILIENCY,
        "notes": notes,
        "note": ("Device and on-premises-location diversity are only partly visible from the API "
                 "(AWS device per connection); confirm the on-premises side separately."),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(check_direct_connect(region="eu-west-1"), indent=2, default=str))
    print(json.dumps(recommend_dx_resilience(region="eu-west-1"), indent=2, default=str))
