# AWS Cross-Account Identity Self-Healing Engine

A defensive cloud-security portfolio project that monitors AWS IAM
activity across accounts, classifies identity-related events, forwards
findings to a local security monitoring stack, and demonstrates
controlled containment against a dedicated test identity.

> **Safety note:** The deployed Lambda is currently configured with
> `ALERT_MODE=audit`. Containment was tested on the dedicated disposable
> user `self-healing-containment-test`; the test access key was
> deactivated. Do not enable containment against real users or
> production identities without explicit authorization, safeguards, and
> a recovery plan.

## Project goals

-   Detect selected IAM identity events in a target AWS account.
-   Forward target-account events to a monitoring-account Lambda through
    EventBridge.
-   Classify events and publish normalized findings to Amazon SQS.
-   Consume findings locally and write JSON records into a
    Wazuh-monitored log file.
-   Generate Wazuh alerts for findings requiring review.
-   Demonstrate a narrowly scoped containment action against a dedicated
    test user's newly created access key.

## Architecture

``` mermaid
flowchart LR
    A["IAM activity<br/>Target AWS account"] --> B["AWS CloudTrail"]
    B --> C["Amazon EventBridge rule"]
    C --> D["Monitoring account<br/>Lambda classifier"]
    D --> E["Amazon SQS findings queue"]
    E --> F["Local Python SQS consumer"]
    F --> G["JSON findings log"]
    G --> H["Wazuh manager"]
    H --> I["Security alerts"]
    D -. "authorized test only" .-> J["Target IAM test user<br/>key deactivation"]
```

## Components

-   **AWS CloudTrail:** records management events.
-   **Amazon EventBridge:** forwards selected events from the target
    account.
-   **AWS Lambda:** filters and classifies events, chooses
    audit/containment behavior, and sends findings to SQS.
-   **Amazon SQS:** decouples cloud event processing from the local
    consumer.
-   **Python consumer (`sqs_to_wazuh.py`):** reads queue messages,
    normalizes fields, and appends JSON findings.
-   **Wazuh:** monitors the JSON file and raises alerts using custom
    rules.
-   **Terraform:** provisions or manages the project's supported AWS
    infrastructure.

## Findings and alerting

The local consumer normalizes fields such as `severity`,
`finding_status`, `eventTime`, `eventName`, `actor`, `sourceIP`,
`target`, `accountId`, `region`, `response_mode`, and `action_taken`.

Custom Wazuh rules used during testing:

  Rule ID    Purpose                         Level
  ---------- ----------------------------- -------
  `100920`   Unreviewed identity finding        10
  `100921`   Failed API call                     7
  `100922`   Authorized baseline event           3

Rule levels are project-specific and should be tuned for the
environment.

## Demonstrated results

-   Target-account `TagUser` events reached the
    Lambda/SQS/local-consumer/Wazuh pipeline.
-   Wazuh generated an alert for an unreviewed `CreateAccessKey` finding
    (rule `100920`, level 10).
-   A controlled containment test on the dedicated test user deactivated
    the newly created test access key.
-   Lambda was returned to `audit` mode after the containment test.
-   The consumer's `convert_finding()` function passed a local test
    preserving `response_mode` and `action_taken`.
-   The deployed Lambda package was inspected and contained both
    `response_mode` and `action_taken` in the finding payload.

**Known verification caveat:** The local log excerpt still contains the
historical `CreateAccessKey` record with `action_taken: "none"` even
though the Lambda log for the containment test reported deactivation.
Historical records are not rewritten after a code deployment. A fresh
event after deployment was not conclusively identified in the final log
excerpt, so do not claim that the post-deployment live metadata path has
been fully re-verified.

## Repository layout (expected)

``` text
.
├── README.md
├── .gitignore
├── docs/
│   ├── ARCHITECTURE.md
│   ├── DEPLOYMENT.md
│   ├── SECURITY.md
│   └── TESTING.md
├── lambda/
│   ├── deployed/
│   │   └── lambda_function.py
│   └── package/
├── sqs_to_wazuh.py
├── wazuh-logs/                 # runtime output; do not commit
├── logs/                       # runtime logs; do not commit
└── terraform/                  # if present in your working tree
```

The actual repository may have additional files or different folder
names; retain the existing implementation and merge these docs into the
current project rather than replacing source code.

## Setup overview

1.  Configure AWS credentials using a dedicated least-privilege profile.
2.  Review Terraform variables and plan before applying infrastructure
    changes.
3.  Deploy the Lambda package and configure environment variables.
4.  Configure cross-account EventBridge forwarding and its target
    permissions.
5.  Create/configure the SQS queue and Lambda permissions.
6.  Start the local Python consumer with its virtual environment.
7.  Configure Wazuh to monitor the JSON findings file and load custom
    rules.
8.  Validate using harmless events and synthetic local records before
    any containment testing.

See [Deployment Guide](docs/DEPLOYMENT.md), [Testing
Guide](docs/TESTING.md), and [Security Notes](docs/SECURITY.md).

## Operational mode

The current intended operating mode is `audit`. Findings are recorded
and alerted on without deactivating keys. Containment should be
restricted to a dedicated disposable test identity unless a separately
reviewed production response policy exists.

## Limitations

-   The local consumer and Wazuh monitoring stack must be running for
    local alerts to be generated from queued findings.
-   The local JSON file is a pipeline integration point, not a durable
    central data store.
-   Event patterns and identity-event classification require
    environment-specific tuning.
-   This project demonstrates a controlled lab workflow; it is not a
    turnkey production SOAR platform.
-   Verify current deployment configuration and test outcomes before
    making claims about a particular live event.

## License

Choose a license before publishing. If you do not intend to grant reuse
rights, do not add a license file by default.
