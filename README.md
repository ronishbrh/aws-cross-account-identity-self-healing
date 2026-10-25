# AWS Cross-Account Identity Self-Healing Engine

A security automation lab combining AWS IAM event monitoring, EventBridge, Lambda, SQS, Terraform, and Wazuh to detect suspicious identity activity and generate security findings.

## Project Goals

- Monitor selected AWS IAM security events.
- Classify identity events and flag findings that require review.
- Process events through AWS Lambda and publish findings to SQS.
- Forward queued findings to a local JSON file monitored by Wazuh.
- Generate Wazuh alerts using custom detection rules.
- Keep response behavior in audit mode during development and verification.

## Architecture

1. AWS IAM events are forwarded through Amazon EventBridge.
2. AWS Lambda evaluates events and creates findings.
3. Amazon SQS queues the findings.
4. `sqs_to_wazuh.py` consumes messages and writes findings to a JSON file.
5. Wazuh monitors that file and evaluates events against custom rules.
6. Terraform manages the infrastructure defined in `main.tf`.

## Key Files

| File | Purpose |
|---|---|
| `main.tf` | Terraform infrastructure definition |
| `detect_identity_events.py` | Identity-event detection and classification |
| `inspect_cloudtrail.py` | CloudTrail event inspection |
| `sqs_to_wazuh.py` | SQS-to-Wazuh findings bridge |
| `lambda/deployed/lambda_function.py` | Lambda handler source |
| `lambda/package/lambda_function.py` | Lambda package source |
| `lambda/test_containment.py` | Containment-safety unit tests |
| `.gitignore` | Excludes local state, credentials, generated output, and backups |

## Validation Completed

- Wazuh generated an alert from a synthetic JSON finding.
- The SQS consumer was running and its logs showed processed `TagUser` findings.
- Nine containment-safety unit tests passed.
- The deployed Lambda was configured with `ALERT_MODE=audit` at the last verification.

These checks validate key components, but do not prove that every event path or live containment action has been tested end to end.

## Safety

- Keep Lambda in audit mode during development.
- Never commit AWS credentials, Terraform state, private keys, runtime findings, or generated deployment archives.
- Treat access-key deactivation as a potentially disruptive action requiring explicit approval and controlled testing.

## Run Tests

From the project root:

```bash
python -m unittest discover -s lambda -p 'test_*.py' -v
