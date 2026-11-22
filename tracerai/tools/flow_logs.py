"""VPC Flow Logs reader (CloudWatch Logs only).

Answers "is traffic to this interface being accepted or rejected" from the VPC
flow log records, as evidence next to the config that the other tools read.

Named for VPC flow logs specifically, because Cloud WAN has its own flow logs.
This reads VPC flow logs and only when they are delivered to CloudWatch Logs; a
flow log delivered to S3 needs Athena and is out of scope here.

    python tracerai/tools/flow_logs.py
"""

import time

import boto3

from tracerai.aws_session import get_session

# Discovered field names for VPC flow logs in the default format, as CloudWatch
# Logs Insights exposes them. A custom flow log format may name fields
# differently, in which case the query needs adjusting.
_QUERY_FIELDS = "@timestamp, interfaceId, srcAddr, dstAddr, srcPort, dstPort, protocol, action, logStatus"


def _norm(account_id, me):
    return None if (not account_id or account_id == me) else account_id


def _resolve_enis(ec2, target: str):
    """Resolve an instance id, ENI id, or private IP to ENI ids plus subnet/vpc."""
    t = target.strip()
    if t.startswith("arn:"):
        t = t.split("/")[-1]
    enis = []
    if t.startswith("eni-"):
        nis = ec2.describe_network_interfaces(NetworkInterfaceIds=[t]).get("NetworkInterfaces", [])
    elif t.startswith("i-"):
        resv = ec2.describe_instances(InstanceIds=[t]).get("Reservations", [])
        nis = [ni for r in resv for inst in r.get("Instances", []) for ni in inst.get("NetworkInterfaces", [])]
    else:
        nis = ec2.describe_network_interfaces(
            Filters=[{"Name": "addresses.private-ip-address", "Values": [t]}]).get("NetworkInterfaces", [])
    for ni in nis:
        enis.append(ni["NetworkInterfaceId"])
    subnet = nis[0].get("SubnetId") if nis else None
    vpc = nis[0].get("VpcId") if nis else None
    return enis, subnet, vpc


def _pick_cloudwatch_flow_log(ec2, enis, subnet, vpc):
    """Find an active VPC flow log that delivers to CloudWatch Logs, preferring
    the most specific resource (ENI, then subnet, then VPC)."""
    resource_ids = [r for r in (enis + [subnet, vpc]) if r]
    if not resource_ids:
        return None, None
    fls = ec2.describe_flow_logs(
        Filters=[{"Name": "resource-id", "Values": resource_ids}]).get("FlowLogs", [])
    by_resource = {}
    for fl in fls:
        by_resource.setdefault(fl.get("ResourceId"), []).append(fl)
    for rid in resource_ids:
        for fl in by_resource.get(rid, []):
            if (fl.get("LogDestinationType") == "cloud-watch-logs"
                    and fl.get("FlowLogStatus") == "ACTIVE"):
                return fl, fls
    return None, fls


def check_vpc_flow_logs(target: str, region: str = None, account_id: str = None,
                        action: str = "REJECT", minutes: int = 60, port: int = None) -> dict:
    """Read VPC flow log records for an interface from CloudWatch Logs.

    target is an instance id, an ENI id, or a private IP. action is REJECT,
    ACCEPT or ALL. Looks back `minutes` and optionally filters a destination
    port. Only works when the VPC flow log is delivered to CloudWatch Logs.
    """
    if not region:
        return {"needs_region": True}
    act = action.upper()
    if act not in ("REJECT", "ACCEPT", "ALL"):
        return {"error": "action must be REJECT, ACCEPT or ALL"}

    me = boto3.client("sts").get_caller_identity()["Account"]
    try:
        session = get_session(account_id=_norm(account_id, me), region=region)
    except Exception as e:
        return {"region": region, "account_id": account_id, "error": str(e)}
    ec2 = session.client("ec2", region_name=region)
    logs = session.client("logs", region_name=region)

    enis, subnet, vpc = _resolve_enis(ec2, target)
    if not enis:
        return {"target": target, "region": region,
                "error": f"could not resolve {target} to a network interface"}

    fl, all_fls = _pick_cloudwatch_flow_log(ec2, enis, subnet, vpc)
    if not fl:
        if all_fls:
            dests = sorted({f.get("LogDestinationType") for f in all_fls})
            return {"target": target, "enis": enis,
                    "note": f"a VPC flow log exists but does not deliver to CloudWatch Logs "
                            f"(destination: {', '.join(dests)}); this tool only reads CloudWatch Logs"}
        return {"target": target, "enis": enis,
                "note": "no VPC flow log is enabled on this interface, its subnet, or its VPC"}

    log_group = fl.get("LogGroupName")
    traffic = fl.get("TrafficType")
    notes = []
    if act == "REJECT" and traffic == "ACCEPT":
        notes.append("this flow log captures ACCEPT only, so it has no REJECT records")
    if act == "ACCEPT" and traffic == "REJECT":
        notes.append("this flow log captures REJECT only, so it has no ACCEPT records")

    eni_list = ", ".join(f'"{e}"' for e in enis)
    q = [f"fields {_QUERY_FIELDS}", f"filter interfaceId in [{eni_list}]"]
    if act != "ALL":
        q.append(f'filter action = "{act}"')
    if port is not None:
        q.append(f"filter dstPort = {int(port)}")
    q.append("sort @timestamp desc")
    q.append("limit 50")
    query_string = " | ".join(q)

    now = int(time.time())
    start = logs.start_query(logGroupName=log_group, startTime=now - minutes * 60,
                             endTime=now, queryString=query_string)
    qid = start["queryId"]
    status, results = "Running", []
    for _ in range(30):
        r = logs.get_query_results(queryId=qid)
        status = r["status"]
        if status in ("Complete", "Failed", "Cancelled", "Timeout"):
            results = r.get("results", [])
            break
        time.sleep(1)
    else:
        logs.stop_query(queryId=qid)
        status = "Timeout"

    records = []
    for row in results:
        rec = {f["field"].lstrip("@"): f["value"] for f in row if f["field"] != "@ptr"}
        records.append(rec)

    return {
        "target": target, "region": region, "account_id": account_id,
        "enis": enis, "vpc_id": vpc, "subnet_id": subnet,
        "flow_log_id": fl.get("FlowLogId"), "log_group": log_group,
        "traffic_type": traffic, "action_queried": act,
        "window_minutes": minutes, "port": port,
        "query_status": status,
        "match_count": len(records),
        "records": records,
        "notes": notes,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(check_vpc_flow_logs("i-REPLACE", region="eu-west-1"), indent=2, default=str))
