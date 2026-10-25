import json
import os
import time
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError

QUEUE_URL = os.environ.get(
    "IDENTITY_FINDINGS_QUEUE_URL",
    "https://sqs.us-east-1.amazonaws.com/686511310473/identity-self-healing-findings",
)
REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
LOG_PATH = Path("wazuh-logs/identity-findings.json")
STATE_PATH = Path("wazuh-logs/processed-sqs-message-ids.json")

SEVERITY_MAP = {
    "critical": "HIGH",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}


def convert_finding(finding):
    return {
        "severity": SEVERITY_MAP.get(
            str(finding.get("severity", "high")).lower(), "HIGH"
        ),
        "finding_status": finding.get("finding_status", "UNREVIEWED"),
        "eventTime": finding.get("timestamp"),
        "eventName": finding.get("event_name", "Unknown"),
        "actor": finding.get("actor", "unknown"),
        "sourceIP": finding.get("source_ip"),
        "target": finding.get("target", finding.get("event_name", "Unknown")),
        "errorCode": finding.get("errorCode"),
        "accountId": finding.get("account_id", "unknown"),
        "region": finding.get("region", "unknown"),
        "recommended_response": finding.get("recommended_response", ""),
        "response_mode": finding.get("response_mode", "audit"),
        "action_taken": "none",
    }


def load_processed_ids():
    if not STATE_PATH.exists():
        return set()
    with STATE_PATH.open(encoding="utf-8") as state_file:
        return set(json.load(state_file))


def save_processed_id(message_id, processed_ids):
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    processed_ids.add(message_id)
    temp_path = STATE_PATH.with_suffix(".tmp")
    with temp_path.open("w", encoding="utf-8") as state_file:
        json.dump(sorted(processed_ids), state_file)
        state_file.flush()
        os.fsync(state_file.fileno())
    temp_path.replace(STATE_PATH)


def append_jsonl(record):
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, separators=(",", ":")) + "\n")
        log_file.flush()
        os.fsync(log_file.fileno())


def main():
    sqs = boto3.client("sqs", region_name=REGION)
    processed_ids = load_processed_ids()

    print(f"Polling SQS queue; writing findings to {LOG_PATH}", flush=True)

    while True:
        try:
            response = sqs.receive_message(
                QueueUrl=QUEUE_URL,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20,
                VisibilityTimeout=60,
            )

            for message in response.get("Messages", []):
                message_id = message["MessageId"]

                if message_id not in processed_ids:
                    finding = json.loads(message["Body"])
                    record = convert_finding(finding)
                    append_jsonl(record)
                    save_processed_id(message_id, processed_ids)
                    print(
                        f"Logged {record['eventName']} ({record['severity']})",
                        flush=True,
                    )
                else:
                    print(f"Skipping already logged SQS message {message_id}", flush=True)

                # Acknowledge only after logging and recording the message ID.
                sqs.delete_message(
                    QueueUrl=QUEUE_URL,
                    ReceiptHandle=message["ReceiptHandle"],
                )


        except (BotoCoreError, ClientError, json.JSONDecodeError, OSError) as exc:
            print(f"Consumer error: {exc}", flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
