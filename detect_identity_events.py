import argparse
import json
import sys
from pathlib import Path

HIGH_PRIORITY = {
    # IAM users and credentials
    "CreateUser",
    "DeleteUser",
    "CreateAccessKey",
    "DeleteAccessKey",
    "UpdateAccessKey",
    "CreateLoginProfile",
    "DeleteLoginProfile",
    "UpdateLoginProfile",
    "CreateVirtualMFADevice",
    "EnableMFADevice",
    "DeactivateMFADevice",
    "DeleteVirtualMFADevice",

    # Roles and trust relationships
    "CreateRole",
    "DeleteRole",
    "UpdateRole",
    "UpdateAssumeRolePolicy",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "PutRolePolicy",
    "DeleteRolePolicy",

    # Policies and permissions
    "CreatePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "DeletePolicy",
    "DeletePolicyVersion",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "PutGroupPolicy",
    "DeleteGroupPolicy",
    "AttachGroupPolicy",
    "DetachGroupPolicy",

    # Group membership
    "CreateGroup",
    "DeleteGroup",
    "AddUserToGroup",
    "RemoveUserFromGroup",
}

MONITORED_EVENTS = HIGH_PRIORITY | {
    # SAML identity providers
    "CreateSAMLProvider",
    "UpdateSAMLProvider",
    "DeleteSAMLProvider",

    # Additional IAM and credential changes
    "UpdateAccountPasswordPolicy",
    "DeleteAccountPasswordPolicy",
    "UpdateSAMLProvider",
    "TagUser",
    "UntagUser",
    "TagRole",
    "UntagRole",
    "TagPolicy",
    "UntagPolicy",
}

# Explicitly reviewed project-setup events.
# Match event type, actor, target, and exact UTC timestamp.
AUTHORIZED_BASELINE = {
    (
        "PutUserPolicy",
        "arn:aws:iam::686511310473:root",
        "terraform-lab",
        "2026-10-19T06:36:29Z",
        "27.34.64.105",
    ),
    (
        "UpdateAssumeRolePolicy",
        "arn:aws:iam::686511310473:root",
        "IdentitySelfHealingTargetRole",
        "2026-10-19T07:26:32Z",
        "27.34.64.105",
    ),
    (
        "AttachRolePolicy",
        "arn:aws:iam::686511310473:root",
        "IdentitySelfHealingTargetRole",
        "2026-10-19T07:25:24Z",
        "27.34.64.105",
    ),
    (
        "PutUserPolicy",
        "arn:aws:iam::686511310473:root",
        "terraform-lab",
        "2026-10-19T06:32:16Z",
        "27.34.64.105",
    ),
    (
        "PutUserPolicy",
        "arn:aws:iam::686511310473:root",
        "terraform-lab",
        "2026-10-19T07:10:34Z",
        "27.34.64.105",
    ),
}


def detect(record):
    event = record.get("eventName", "Unknown")

    if event not in MONITORED_EVENTS:
        return None

    identity = record.get("userIdentity") or {}
    params = record.get("requestParameters") or {}

    target = (
        params.get("userName")
        or params.get("roleName")
        or params.get("policyName")
        or "Unknown"
    )
    actor = identity.get("arn", "Unknown")
    event_time = record.get("eventTime", "Unknown")
    error = record.get("errorCode")

    source_ip = record.get("sourceIPAddress", "Unknown")
    baseline_key = (event, actor, target, event_time, source_ip)
    authorized = baseline_key in AUTHORIZED_BASELINE

    if error:
        severity = "REVIEW"
        status = "FAILED_API_CALL"
    elif authorized:
        severity = "INFO"
        status = "AUTHORIZED_BASELINE"
    elif event in HIGH_PRIORITY:
        severity = "HIGH"
        status = "UNREVIEWED"
    else:
        severity = "MEDIUM"
        status = "UNREVIEWED"

    return {
        "severity": severity,
        "finding_status": status,
        "eventTime": event_time,
        "eventName": event,
        "actor": actor,
        "sourceIP": source_ip,
        "target": target,
        "errorCode": error,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Detect suspicious AWS identity events in CloudTrail JSON."
    )
    parser.add_argument(
        "--wazuh-log",
        type=Path,
        help="Append each finding as a JSONL record to this file.",
    )
    args = parser.parse_args()

    try:
        data = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON input: {exc}", file=sys.stderr)
        return 2

    if not isinstance(data, dict) or not isinstance(data.get("Records"), list):
        print(
            "Invalid CloudTrail document: expected a JSON object "
            "containing a Records list.",
            file=sys.stderr,
        )
        return 2

    records = data["Records"]

    if not all(isinstance(record, dict) for record in records):
        print(
            "Invalid CloudTrail document: every Records item must be an object.",
            file=sys.stderr,
        )
        return 2

    findings = [
        finding
        for record in records
        if (finding := detect(record)) is not None
    ]

    if args.wazuh_log and findings:
        try:
            args.wazuh_log.parent.mkdir(parents=True, exist_ok=True)
            with args.wazuh_log.open("a", encoding="utf-8") as log_file:
                for finding in findings:
                    log_file.write(
                        json.dumps(finding, separators=(",", ":")) + "\n"
                    )
        except OSError as exc:
            print(f"Unable to write Wazuh findings: {exc}", file=sys.stderr)
            return 2

    print(json.dumps({
        "totalEvents": len(records),
        "identityFindings": len(findings),
        "authorizedBaselineCount": sum(
            item["finding_status"] == "AUTHORIZED_BASELINE"
            for item in findings
        ),
        "unreviewedCount": sum(
            item["finding_status"] == "UNREVIEWED"
            for item in findings
        ),
        "failedApiCallCount": sum(
            item["finding_status"] == "FAILED_API_CALL"
            for item in findings
        ),
        "reviewRequiredCount": sum(
            item["finding_status"] in ("UNREVIEWED", "FAILED_API_CALL")
            for item in findings
        ),
        "findings": findings,
    }, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
