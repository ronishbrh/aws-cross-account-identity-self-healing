# Testing and Validation Record

## Confirmed in the lab

  --------------------------------------------------------------------------------
  Test                                Observed result
  ----------------------------------- --------------------------------------------
  Target-account `TagUser` event      Findings appeared in the local Wazuh
  processing                          findings log

  Wazuh unreviewed finding rule       Rule `100920`, level 10, generated an alert
                                      for a `CreateAccessKey` finding

  Dedicated test-user containment     Lambda logs reported
                                      `test_access_key_deactivated`; user
                                      confirmed the newly created test key became
                                      inactive

  Post-test safety configuration      Lambda environment returned to
                                      `ALERT_MODE=audit`

  Consumer mapping unit test          Synthetic input preserved
                                      `response_mode=contain` and
                                      `action_taken=test_access_key_deactivated`

  Deployed Lambda package inspection  Deployed ZIP contained `response_mode` and
                                      `action_taken` fields in the finding payload

  Lambda deployment state             Function active; last update successful
  --------------------------------------------------------------------------------

## Known caveat

A historical `CreateAccessKey` record in the local JSON file has
`response_mode: "contain"` but `action_taken: "none"`. The Lambda log
for that event reported that the test key was deactivated. The consumer
code originally hardcoded `action_taken` to `"none"`, and the Lambda
finding payload originally omitted the action field. Those code paths
were corrected and deployed, but old records remain unchanged.

The final excerpt did not establish that a fresh post-deployment event
was processed. Therefore, the corrected end-to-end metadata path should
be described as code-reviewed and locally unit-tested, not fully
re-verified live.

## Safe future smoke test

If a future verification is needed, use a harmless `TagUser` event on
the dedicated test identity while `ALERT_MODE=audit`. Verify the event
appears in Lambda logs, the SQS consumer log, the newest JSON finding,
and the Wazuh alert. Do not create another access key solely to test
metadata propagation.

## Test hygiene

-   Label synthetic records clearly.
-   Do not treat synthetic events as real AWS telemetry.
-   Preserve evidence without committing raw logs to a public
    repository.
-   Keep historical results separate from post-fix validation.
