# Architecture and Data Flow

## Overview

The project separates cloud event collection and classification from
local security monitoring.

1.  IAM management activity is recorded by CloudTrail in the target
    account.
2.  An EventBridge rule selects configured identity-related events and
    forwards them to the monitoring account.
3.  The Lambda handler filters/classifies the event and constructs a
    normalized finding.
4.  Lambda sends the finding to Amazon SQS.
5.  A local Python consumer polls SQS and converts the finding into the
    field schema expected by Wazuh.
6.  The consumer appends a JSON object to the monitored findings log.
7.  Wazuh decodes the JSON and applies local rules to generate alerts.

## Main components

### EventBridge

The target-account rule is configured for a selected set of IAM events,
including `TagUser` and `CreateAccessKey` for the lab. The event pattern
must explicitly include the intended test identity or the relevant event
will not be forwarded.

### Lambda classifier and response

The handler uses `TEST_USER` to scope the test containment action and
`ALERT_MODE` to select audit versus containment behavior. In the current
configuration, `ALERT_MODE=audit`.

Containment behavior was demonstrated only against the dedicated test
user. The code and IAM permissions should be reviewed before reuse.

### SQS consumer

The consumer's `convert_finding()` maps incoming payload fields into
Wazuh's log schema. It supports snake_case and selected camelCase
variants and preserves `response_mode` and `action_taken` from the
incoming finding.

### Wazuh

The JSON findings file is mounted/monitored by Wazuh at
`/var/log/aws-identity-self-healing/identity-findings.json`. The local
project writes to `wazuh-logs/identity-findings.json`.

Custom rules used in the lab:

-   `100920`: `UNREVIEWED` finding, level 10.
-   `100921`: `FAILED_API_CALL`, level 7.
-   `100922`: authorized baseline event, level 3.

## Trust boundaries

-   Target AWS account: source of monitored IAM events and location of
    the dedicated test identity.
-   Monitoring AWS account: Lambda, SQS, and monitoring-side
    permissions.
-   Local Kali host: SQS consumer and Wazuh/Docker monitoring stack.
-   Repository: code and documentation only; it must not contain
    credentials, live log data, Terraform state, or deployment ZIPs.

## Failure considerations

-   Incorrect EventBridge event patterns can prevent events from
    reaching Lambda.
-   Incorrect Lambda execution permissions can prevent cross-account
    actions or SQS publication.
-   A stopped consumer can leave messages queued.
-   A mismatched JSON schema can lose metadata or cause rules not to
    match.
-   Wazuh may ingest a record without the intended rule matching; verify
    both the raw record and alert.
-   Old log records are not retroactively rewritten when code changes.
