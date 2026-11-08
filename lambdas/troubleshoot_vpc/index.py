"""
TracerAI — TroubleshootVPCConnectivity Lambda tool.

Invoked by the Amazon Bedrock Agent action group. Performs READ-ONLY boto3
calls to gather the configuration needed to diagnose VPC-to-VPC connectivity.

PoC stub: wire real logic into `troubleshoot_vpc()`. Keep every API call
read-only (Describe*/Get*/List*).
"""

import json
import boto3

ec2 = boto3.client("ec2")


def troubleshoot_vpc(source_vpc_id: str, target_vpc_id: str) -> dict:
    """Gather read-only evidence for a VPC-to-VPC connectivity question.

    PoC: returns raw route tables + security groups for both VPCs so the
    agent can reason over them. Extend with TGW route lookups, NACLs, etc.
    """
    def _vpc_facts(vpc_id: str) -> dict:
        route_tables = ec2.describe_route_tables(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["RouteTables"]
        security_groups = ec2.describe_security_groups(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )["SecurityGroups"]
        return {"routeTables": route_tables, "securityGroups": security_groups}

    return {
        "source": {"vpcId": source_vpc_id, **_vpc_facts(source_vpc_id)},
        "target": {"vpcId": target_vpc_id, **_vpc_facts(target_vpc_id)},
    }


def lambda_handler(event, context):
    """Bedrock Agent action-group entrypoint.

    Bedrock passes parameters in `event`; the response must echo back the
    action group / apiPath and carry the tool result in `responseBody`.
    """
    params = {p["name"]: p["value"] for p in event.get("parameters", [])}
    source_vpc_id = params.get("sourceVpcId")
    target_vpc_id = params.get("targetVpcId")

    result = troubleshoot_vpc(source_vpc_id, target_vpc_id)

    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": event.get("actionGroup"),
            "apiPath": event.get("apiPath"),
            "httpMethod": event.get("httpMethod"),
            "httpStatusCode": 200,
            "responseBody": {
                "application/json": {"body": json.dumps(result)}
            },
        },
    }
