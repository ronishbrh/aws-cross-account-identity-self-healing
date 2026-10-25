
import json
import os
import logging
import boto3
from datetime import datetime, timezone

ALERT_MODE = os.getenv("ALERT_MODE", "audit").lower()
QUEUE_URL = os.environ["IDENTITY_FINDINGS_QUEUE_URL"]

TARGET_ACCOUNT_ID = "935776475361"
TARGET_ROLE_ARN = (
    "arn:aws:iam::935776475361:role/IdentitySelfHealingTargetRole"
)
TEST_USER = os.getenv("TEST_USER", "self-healing-test-user")

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sqs = boto3.client("sqs")
sts = boto3.client("sts")

SEVERITY = {
    "CreateAccessKey": "high",
    "AttachUserPolicy": "critical",
    "PutUserPolicy": "critical",
    "AttachRolePolicy": "critical",
    "CreateLoginProfile": "high",
    "CreatePolicyVersion": "high",
    "TagUser": "medium",
}

RECOMMENDATIONS = {
    "CreateAccessKey": "Review the new access key; verify the actor and key owner.",
    "AttachUserPolicy": "Review the attached policy and assess excessive permissions.",
    "PutUserPolicy": "Inspect the inline policy for unauthorized privilege escalation.",
    "AttachRolePolicy": "Review the role policy attachment and effective permissions.",
    "CreateLoginProfile": "Verify whether console access was intentionally created.",
    "CreatePolicyVersion": "Review the new policy version and its default-version status.",
    "TagUser": "Review the changed user tags for unexpected security or access-control changes.",
}


def contain_test_access_key(detail):
    """Deactivate a test user's newly created key only in explicit contain mode."""
    if ALERT_MODE != "contain":
        return "none"

    # Require a successful CreateAccessKey event for the dedicated test user.
    if detail.get("eventName") != "CreateAccessKey":
        return "none"

    if detail.get("errorCode"):
        return "none"

    request = detail.get("requestParameters") or {}
    user_name = request.get("userName")

    if user_name != TEST_USER:
        logger.warning("Containment skipped: target is not the test user")
        return "none"

    response_elements = detail.get("responseElements") or {}
    access_key = response_elements.get("accessKey") or {}
    access_key_id = access_key.get("accessKeyId")

    if not access_key_id or not access_key_id.startswith("AKIA"):
        logger.warning("Containment skipped: no valid access key ID in event")
        return "none"

    target_account = (
        detail.get("recipientAccountId")
        or detail.get("userIdentity", {}).get("accountId")
    )

    if target_account != TARGET_ACCOUNT_ID:
        logger.warning("Containment skipped: unexpected target account")
        return "none"

    assumed = sts.assume_role(
        RoleArn=TARGET_ROLE_ARN,
        RoleSessionName="IdentitySelfHealingContainment",
        DurationSeconds=900,
    )

    credentials = assumed["Credentials"]
    target_iam = boto3.client(
        "iam",
        region_name="us-east-1",
        aws_access_key_id=credentials["AccessKeyId"],
        aws_secret_access_key=credentials["SecretAccessKey"],
        aws_session_token=credentials["SessionToken"],
    )

    # Verify that the event's key ID belongs to the dedicated test user.
    key_response = target_iam.list_access_keys(UserName=TEST_USER)
    owned_key_ids = {
        item.get("AccessKeyId")
        for item in key_response.get("AccessKeyMetadata", [])
    }

    if access_key_id not in owned_key_ids:
        logger.warning(
            "Containment skipped: event key ID is not owned by the test user"
        )
        return "none"

    target_iam.update_access_key(
        UserName=TEST_USER,
        AccessKeyId=access_key_id,
        Status="Inactive",
    )

    logger.warning(
        json.dumps({
            "message": "Test access key deactivated",
            "target_user": TEST_USER,
            "target_account": TARGET_ACCOUNT_ID,
            "event_name": "CreateAccessKey",
        })
    )
    return "test_access_key_deactivated"


def lambda_handler(event, context=None):
    """Classify monitored IAM events and publish findings to SQS."""

    detail = event.get("detail") or event

    logger.info(json.dumps({
        "message": "IAM event received",
        "source": event.get("source", "direct-test"),
        "detail_type": event.get("detail-type", "direct-test"),
        "event_name": detail.get("eventName"),
        "event_source": detail.get("eventSource"),
        "event_account": event.get("account"),
        "recipient_account": detail.get("recipientAccountId"),
        "target_user": (detail.get("requestParameters") or {}).get("userName"),
        "error_code": detail.get("errorCode"),
    }))

    if "detail" in event:
        if (
            event.get("source") != "aws.iam"
            or event.get("detail-type") != "AWS API Call via CloudTrail"
        ):
            return {
                "status": "ignored",
                "reason": "Not a supported IAM CloudTrail event",
            }

        detail = event["detail"]

        if detail.get("eventSource") != "iam.amazonaws.com":
            return {
                "status": "ignored",
                "reason": "Unexpected event source",
            }
    else:
        # Direct-test input: caller supplies event detail.
        detail = event

    event_name = detail.get("eventName", "")

    logger.info(json.dumps({
        "message": "IAM event filter diagnostic",
        "event_name": event_name,
        "event_name_type": type(event_name).__name__,
        "is_monitored": event_name in SEVERITY,
        "monitored_events": sorted(SEVERITY.keys()),
    }))

    if event_name not in SEVERITY:
        logger.warning(json.dumps({
            "message": "IAM event ignored",
            "reason": "Event is not in the monitored IAM event list",
            "event_name": event_name,
            "monitored_events": sorted(SEVERITY.keys()),
        }))
        return {
            "status": "ignored",
            "reason": "Event is not in the monitored IAM event list",
            "event_name": event_name,
        }

    identity = detail.get("userIdentity", {})
    target_account = (
        detail.get("recipientAccountId")
        or identity.get("accountId")
        or event.get("account", "unknown")
    )

    action_taken = "none"
    try:
        action_taken = contain_test_access_key(detail)
    except Exception:
        logger.exception("Guarded containment attempt failed")
        # Do not hide a failed attempt; the finding still goes to SQS.
        action_taken = "containment_failed"

    finding = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_time": detail.get("eventTime"),
        "status": "detected",
        "event_name": event_name,
        "severity": SEVERITY[event_name],
        "recommended_response": RECOMMENDATIONS[event_name],
        "actor": (
            identity.get("userName")
            or identity.get("arn")
            or identity.get("principalId", "unknown")
        ),
        "account_id": target_account,
        "region": detail.get("awsRegion") or event.get("region", "unknown"),
        "target": (
            (detail.get("requestParameters") or {}).get("userName")
            or (detail.get("requestParameters") or {}).get("roleName")
            or event_name
        ),
        "source_ip": detail.get("sourceIPAddress"),
        "response_mode": ALERT_MODE,
        "action_taken": action_taken,
    }

    logger.info(json.dumps({
        "message": "IAM event classified",
        "event_name": event_name,
        "severity": finding["severity"],
        "response_mode": ALERT_MODE,
        "action_taken": action_taken,
    }))

    response = sqs.send_message(
        QueueUrl=QUEUE_URL,
        MessageBody=json.dumps(finding),
    )

    logger.info(json.dumps({
        "message": "Finding sent to SQS",
        "event_name": event_name,
        "sqs_message_id": response["MessageId"],
    }))

    return {
        **finding,
        "queue_status": "sent",
    }
