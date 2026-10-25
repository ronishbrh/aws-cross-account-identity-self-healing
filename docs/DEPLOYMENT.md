# Deployment and Operations Guide

This guide documents the workflow at a high level. Review the current
infrastructure and configuration in the repository before running
commands; resource names and paths may vary.

## Prerequisites

-   AWS CLI configured with separate, least-privilege access to the
    monitoring and target accounts.
-   Terraform installed, if the Terraform configuration is used.
-   Python and the project's virtual environment.
-   Docker Compose and Wazuh configured for local JSON ingestion.
-   Access to the Lambda, EventBridge rule, SQS queue, and target test
    user.

## Safe deployment workflow

1.  Confirm the active AWS account and region before making changes.
2.  Inspect Terraform variables and backend configuration. Never commit
    state files or plan files.
3.  Run `terraform fmt -check` and `terraform validate` where supported.
4.  Run `terraform plan` and review every proposed change before
    applying.
5.  Package the intended Lambda source file and any required project
    modules.
6.  Deploy the Lambda package to the intended function and region.
7.  Wait for the Lambda update to finish, then verify its state and
    environment.
8.  Keep `ALERT_MODE=audit` for normal operation.
9.  Confirm the EventBridge target and SQS queue permissions without
    changing trust relationships unnecessarily.
10. Start the local SQS consumer and verify the monitored JSON file is
    writable.
11. Confirm Wazuh can parse the JSON and the intended custom rules are
    loaded.

## Lambda configuration

The tested function is named `identity-self-healing-handler` in
`us-east-1`.

Relevant environment variables: - `ALERT_MODE`: currently `audit`. -
`TEST_USER`: dedicated lab identity, currently
`self-healing-containment-test`.

Do not copy account-specific identifiers or role ARNs from a personal
lab into a public template without reviewing them. Do not broaden
cross-account trust policies just to make a command succeed.

## Starting the local consumer

From the project directory, use the existing virtual environment and
configured AWS credentials. Example:

``` bash
nohup .venv/bin/python -u sqs_to_wazuh.py >> logs/sqs-consumer.log 2>&1 &
```

Create the `logs/` directory if needed. Confirm the process and inspect
the log when troubleshooting. Avoid running multiple consumers
unintentionally.

## Operational checks

Use read-only checks first: - Lambda state and last update status. -
Lambda environment mode. - EventBridge rule enabled state and target
configuration. - SQS queue metrics and approximate message count. -
Consumer process and latest log entries. - Latest JSON record and Wazuh
alert.

Do not repeatedly run health checks once the relevant state is
established. If a check produces no output, determine whether the log
group/stream or event time range is correct before assuming failure.

## Rollback

If a deployment behaves unexpectedly: 1. Keep response mode in `audit`.
2. Redeploy a known-good reviewed Lambda package or restore the prior
published version if available. 3. Do not reactivate/deactivate any keys
automatically as part of a rollback unless explicitly approved. 4.
Record the change and verify the configuration after rollback.
