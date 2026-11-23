"""Route 53 inspection tools.

Read-only Route 53 helpers: list hosted zones, describe record sets (with the
routing policy, alias and health-check details folded in), and read a health
check's live status.

Teaching notes (why the file looks like this):
  * Route 53 for hosted zones, records and health checks is a GLOBAL service.
    Unlike EC2, there is no per-region data, so these tools take no region and
    the client is pinned to us-east-1 (the same pattern cross_account.py uses
    for networkmanager). route53resolver IS regional, but that is a different
    service and not covered here.
  * Each tool is a plain function that returns a dict. The @tool wrapper that
    the model sees lives in agent.py; its docstring is the model's only guide.
  * Risky calls are wrapped so a missing permission becomes a note, not a crash.
  * The routing policy is not a field you can read directly. Route 53 reports it
    implicitly by WHICH field is present on the record set, so _routing_policy()
    infers it. That inference is the heart of this file; read it first.

    python tracerai/tools/route53.py
"""

import boto3

from tracerai.aws_session import get_session
from tracerai.tools.cross_account import _assume_failure_note


def _r53(account_id: str = None):
    """A Route 53 client, in this account or another (assumes the read-only role).

    Route 53 is global, so the region is only needed to build the session; the
    client talks to the global endpoint regardless. us-east-1 is the convention.
    """
    if account_id:
        session = get_session(account_id=account_id, region="us-east-1")
        return session.client("route53")
    return boto3.client("route53", region_name="us-east-1")


def _zone_id(raw: str) -> str:
    """Hosted zone ids come back as '/hostedzone/Z123'. The API also accepts the
    bare 'Z123'. Normalize to the bare id so callers can pass either form."""
    return (raw or "").split("/")[-1]


def _routing_policy(rrset: dict) -> str:
    """Infer the routing policy from which optional field is present.

    Route 53 has no 'policy' field. A record with no SetIdentifier is 'simple';
    otherwise exactly one of these fields decides the policy. Order matters only
    in that each policy sets its own field, so we check each. This is the single
    most useful thing this file teaches: the policy is implied by shape.
    """
    if "SetIdentifier" not in rrset:
        return "simple"
    if "Weight" in rrset:
        return "weighted"
    if "Region" in rrset:
        return "latency"
    if "GeoLocation" in rrset:
        return "geolocation"
    if "GeoProximityLocation" in rrset:
        return "geoproximity"
    if "Failover" in rrset:
        return "failover"
    if "MultiValueAnswer" in rrset:
        return "multivalue"
    # A SetIdentifier with none of the above is unexpected; say so rather than
    # guessing 'simple', which would be wrong and hide a real oddity.
    return "unknown (has SetIdentifier but no policy field)"


def _record_summary(rrset: dict) -> dict:
    """Flatten one ResourceRecordSet into the fields a human actually asks about.

    This answers, for one record: is it an alias, does it evaluate target
    health, what routing policy is it, which health check is attached, and the
    per-policy specifics (weight / region / geo / failover role).
    """
    alias = rrset.get("AliasTarget")  # present only on alias records
    summary = {
        "name": rrset.get("Name"),
        "type": rrset.get("Type"),
        "routing_policy": _routing_policy(rrset),
        "is_alias": bool(alias),
        "set_identifier": rrset.get("SetIdentifier"),
        "health_check_id": rrset.get("HealthCheckId"),
        "ttl": rrset.get("TTL"),
        # Plain (non-alias) records carry their answers in ResourceRecords.
        "values": [r.get("Value") for r in rrset.get("ResourceRecords", [])],
    }

    if alias:
        # Alias records have no TTL and no ResourceRecords; the answer is the
        # target, and EvaluateTargetHealth is the alias-specific health toggle.
        summary["alias_target"] = {
            "dns_name": alias.get("DNSName"),
            "hosted_zone_id": _zone_id(alias.get("HostedZoneId")),
            "evaluate_target_health": alias.get("EvaluateTargetHealth"),
        }

    # Per-policy specifics, included only when relevant so the dict stays small.
    policy = summary["routing_policy"]
    if policy == "weighted":
        summary["weight"] = rrset.get("Weight")
    elif policy == "latency":
        summary["region"] = rrset.get("Region")
    elif policy == "geolocation":
        summary["geo_location"] = rrset.get("GeoLocation")
    elif policy == "geoproximity":
        summary["geo_proximity"] = rrset.get("GeoProximityLocation")
    elif policy == "failover":
        summary["failover_role"] = rrset.get("Failover")  # PRIMARY or SECONDARY
    elif policy == "multivalue":
        summary["multivalue_answer"] = rrset.get("MultiValueAnswer")
    return summary


def list_hosted_zones(account_id: str = None) -> dict:
    """List every Route 53 hosted zone, public and private.

    Returns each zone's id, name, whether it is private, its record count and
    comment. Private zones are the ones that matter for VPC DNS.
    """
    try:
        client = _r53(account_id)
    except Exception as e:
        return {"account_id": account_id, "error": _assume_failure_note(account_id, e)}

    zones = []
    try:
        # Route 53 list calls paginate; boto3 paginators hide the token loop.
        for page in client.get_paginator("list_hosted_zones").paginate():
            for z in page.get("HostedZones", []):
                zones.append({
                    "zone_id": _zone_id(z.get("Id")),
                    "name": z.get("Name"),
                    "private": z.get("Config", {}).get("PrivateZone", False),
                    "record_count": z.get("ResourceRecordSetCount"),
                    "comment": z.get("Config", {}).get("Comment"),
                })
    except Exception as e:
        return {"account_id": account_id, "error": f"could not list hosted zones: {e}"}
    return {"account_id": account_id, "zone_count": len(zones), "hosted_zones": zones}


def describe_records(zone_id: str = None, zone_name: str = None, record_name: str = None,
                     record_type: str = None, account_id: str = None) -> dict:
    """Describe the record sets in a hosted zone, with routing policy and health folded in.

    Give a zone_id (preferred) or a zone_name. Optionally filter to one
    record_name (and record_type) to answer "show me app.internal". Each record
    comes back summarized by _record_summary: alias or not, evaluate target
    health, routing policy, attached health check, and the per-policy specifics.
    """
    try:
        client = _r53(account_id)
    except Exception as e:
        return {"account_id": account_id, "error": _assume_failure_note(account_id, e)}

    # Resolve a zone name to an id when the caller gave a name.
    if not zone_id and zone_name:
        try:
            name = zone_name if zone_name.endswith(".") else zone_name + "."
            matches = []
            for page in client.get_paginator("list_hosted_zones").paginate():
                for z in page.get("HostedZones", []):
                    if z.get("Name") == name:
                        matches.append(_zone_id(z.get("Id")))
            if not matches:
                return {"error": f"no hosted zone named {zone_name}"}
            # A public and a private zone can share a name (split-horizon); say so.
            if len(matches) > 1:
                return {"error": f"more than one zone named {zone_name}; pass zone_id",
                        "zone_ids": matches}
            zone_id = matches[0]
        except Exception as e:
            return {"error": f"could not resolve zone name {zone_name}: {e}"}

    if not zone_id:
        return {"error": "give a zone_id or a zone_name"}

    records = []
    try:
        for page in client.get_paginator("list_resource_record_sets").paginate(
                HostedZoneId=zone_id):
            for rrset in page.get("ResourceRecordSets", []):
                records.append(_record_summary(rrset))
    except Exception as e:
        return {"zone_id": zone_id, "error": f"could not list record sets: {e}"}

    # Optional client-side filter. Record names are stored with a trailing dot.
    if record_name:
        want = record_name if record_name.endswith(".") else record_name + "."
        records = [r for r in records if r["name"] == want]
    if record_type:
        records = [r for r in records if r["type"] == record_type.upper()]

    return {"account_id": account_id, "zone_id": zone_id,
            "record_count": len(records), "records": records}


def check_health_check(health_check_id: str, account_id: str = None) -> dict:
    """Read a health check's config and its live per-checker status.

    get_health_check returns the configuration (type, target, thresholds).
    get_health_check_status returns what each Route 53 checker currently sees.
    Route 53 does NOT hand you a single healthy boolean, so this computes one
    from the observations (healthy when every checker reports Success) and is
    honest when it cannot: a CALCULATED or CLOUDWATCH_METRIC health check has no
    endpoint observations, so the status call returns nothing to score.
    """
    try:
        client = _r53(account_id)
    except Exception as e:
        return {"account_id": account_id, "error": _assume_failure_note(account_id, e)}

    config = None
    try:
        hc = client.get_health_check(HealthCheckId=health_check_id)["HealthCheck"]
        cfg = hc.get("HealthCheckConfig", {})
        config = {
            "type": cfg.get("Type"),  # HTTP, HTTPS, TCP, CALCULATED, CLOUDWATCH_METRIC, ...
            "target": cfg.get("FullyQualifiedDomainName") or cfg.get("IPAddress"),
            "port": cfg.get("Port"),
            "resource_path": cfg.get("ResourcePath"),
            "request_interval": cfg.get("RequestInterval"),
            "failure_threshold": cfg.get("FailureThreshold"),
            "inverted": cfg.get("Inverted"),
            "measure_latency": cfg.get("MeasureLatency"),
        }
    except Exception as e:
        return {"health_check_id": health_check_id,
                "error": f"could not read health check config: {e}"}

    # Live status per checker. Only endpoint checks (HTTP/HTTPS/TCP) return
    # observations; calculated and CloudWatch-metric checks do not.
    observations, status_note, healthy = [], None, None
    try:
        resp = client.get_health_check_status(HealthCheckId=health_check_id)
        for o in resp.get("HealthCheckObservations", []):
            report = o.get("StatusReport", {})
            observations.append({
                "region": o.get("Region"),
                "checker_ip": o.get("IPAddress"),
                "status": report.get("Status"),
                "checked_time": str(report.get("CheckedTime")),
            })
        if observations:
            # A checker status string starts with "Success" when that checker
            # sees the endpoint as healthy. All Success => healthy.
            healthy = all((o["status"] or "").startswith("Success") for o in observations)
        else:
            status_note = ("no per-checker observations returned; this is expected for a "
                           "CALCULATED or CLOUDWATCH_METRIC health check, whose health comes "
                           "from child checks or a CloudWatch alarm, not endpoint probes")
    except Exception as e:
        status_note = f"could not read health check status: {e}"

    result = {"account_id": account_id, "health_check_id": health_check_id,
              "config": config, "healthy": healthy, "observations": observations}
    if status_note:
        result["status_note"] = status_note
    return result


if __name__ == "__main__":
    import json
    # Safe read: list the hosted zones in the current account.
    print(json.dumps(list_hosted_zones(), indent=2))
