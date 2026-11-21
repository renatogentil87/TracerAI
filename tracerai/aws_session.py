"""AWS session helper.

Builds a boto3 session for the current account, or assumes a read-only role in
another account for cross-account discovery. The role to assume and the external
id come from the environment so nothing account specific is hardcoded:

    TRACERAI_ROLE_NAME    the role to assume in the target account
                          (default: TracerAI-ReadOnly)
    TRACERAI_EXTERNAL_ID  the external id the role's trust policy requires
"""

import os

import boto3

DEFAULT_ROLE_NAME = "TracerAI-ReadOnly"


def get_session(account_id: str = None, region: str = None,
                role_name: str = None, external_id: str = None) -> boto3.Session:
    """Return a boto3 session.

    With no account_id, use the current credentials. With an account_id, assume
    the read-only role in that account and return a session for those temporary
    credentials. Raises if the role cannot be assumed; callers handle that.
    """
    if not account_id:
        return boto3.Session(region_name=region)

    role_name = role_name or os.getenv("TRACERAI_ROLE_NAME", DEFAULT_ROLE_NAME)
    external_id = external_id or os.getenv("TRACERAI_EXTERNAL_ID")

    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    kwargs = {"RoleArn": role_arn, "RoleSessionName": "tracerai-discovery"}
    if external_id:
        kwargs["ExternalId"] = external_id

    creds = boto3.client("sts").assume_role(**kwargs)["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name=region,
    )
