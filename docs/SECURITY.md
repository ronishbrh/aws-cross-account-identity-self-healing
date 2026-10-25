# Security Notes

## Scope and authorization

This is a defensive lab project. Deploy and test only in AWS accounts
and identities you own or are explicitly authorized to administer.

## Containment safeguards

-   Current operational mode: `audit`.
-   The containment demonstration used only the dedicated disposable
    test user `self-healing-containment-test`.
-   The newly created test access key was confirmed inactive after the
    containment test.
-   Existing keys on other users must not be modified.
-   Do not enable containment for production identities without a
    documented approval, narrow targeting, safeguards against false
    positives, and a recovery process.

## Secrets and sensitive data --- never commit

Exclude at least: - AWS credentials/configuration files or session
tokens. - `.env` files and secrets. - Private keys, certificates, and
generated TLS material. - Terraform state, backups, and plan files. -
CloudTrail archives and raw production logs. - Runtime Wazuh findings
and consumer logs. - Lambda deployment ZIPs if they include
environment-specific or sensitive material.

Before publishing, review the full staged diff and scan for access keys,
tokens, account IDs that should remain private, public IPs, usernames,
internal paths, and other environment-specific details.

## IAM best practices

-   Use least-privilege policies.
-   Keep cross-account trust scoped to the required principal.
-   Do not use root credentials for routine deployment.
-   Use MFA and temporary credentials where possible.
-   Do not disable logging or weaken firewall/security controls to make
    the demo easier.
-   Review permissions for `iam:UpdateAccessKey` and other containment
    actions carefully.

## Disclosure

Document the project as a lab demonstration, not a production-ready
managed service. The event classifier is not a substitute for
comprehensive identity threat detection, approval workflows, and change
management.
