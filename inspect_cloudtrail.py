
import gzip
import json
import subprocess
import sys
from collections import Counter


def get_target(record):
    params = record.get("requestParameters") or {}

    for key in (
        "userName",
        "roleName",
        "policyName",
        "groupName",
        "accessKeyId",
        "sAMLProviderArn",
    ):
        value = params.get(key)
        if value:
            return str(value)

    resources = record.get("resources") or []
    if resources and isinstance(resources[0], dict):
        return resources[0].get("ARN", "Unknown")

    return "Unknown"


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: /usr/bin/python3 inspect_cloudtrail.py <s3-uri>",
            file=sys.stderr,
        )
        return 1

    s3_uri = sys.argv[1]

    try:
        result = subprocess.run(
            ["aws", "s3", "cp", s3_uri, "-"],
            capture_output=True,
            check=True,
        )

        try:
            raw_data = gzip.decompress(result.stdout)
        except gzip.BadGzipFile:
            # Support an uncompressed JSON object too.
            raw_data = result.stdout

        data = json.loads(raw_data)

    except subprocess.CalledProcessError as exc:
        print(
            "AWS CLI failed. Check credentials, permissions, and S3 URI.",
            file=sys.stderr,
        )
        if exc.stderr:
            print(exc.stderr.decode(errors="replace")[:500], file=sys.stderr)
        return 1
    except (OSError, EOFError, gzip.BadGzipFile, json.JSONDecodeError) as exc:
        print(f"Could not read CloudTrail log: {exc}", file=sys.stderr)
        return 1

    if not isinstance(data, dict) or not isinstance(data.get("Records"), list):
        print(
            "Invalid CloudTrail document: expected a Records list.",
            file=sys.stderr,
        )
        return 2

    records = data["Records"]
    if not all(isinstance(record, dict) for record in records):
        print("Invalid CloudTrail document: Records must contain objects.",
              file=sys.stderr)
        return 2

    print(f"Total events: {len(records)}")
    print("\nEvent counts:")

    for event, count in Counter(
        record.get("eventName", "Unknown") for record in records
    ).most_common():
        print(f"{count:3}  {event}")

    print("\nEvent details:")
    for record in records:
        identity = record.get("userIdentity") or {}
        actor = identity.get("arn", "Unknown")

        print(
            f"{record.get('eventTime', 'Unknown')} | "
            f"{record.get('eventName', 'Unknown')} | "
            f"actor={actor} | "
            f"sourceIP={record.get('sourceIPAddress', 'Unknown')} | "
            f"target={get_target(record)} | "
            f"error={record.get('errorCode') or 'None'}"
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
