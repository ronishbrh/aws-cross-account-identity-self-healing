import importlib.util
import os
import unittest
from unittest.mock import Mock, patch

os.environ.setdefault(
    "IDENTITY_FINDINGS_QUEUE_URL",
    "https://example.invalid/test-queue",
)

MODULE_PATH = os.path.join(
    os.path.dirname(__file__),
    "deployed",
    "lambda_function.py",
)

spec = importlib.util.spec_from_file_location(
    "lambda_function",
    MODULE_PATH,
)
handler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handler)


class ContainmentGuardTests(unittest.TestCase):
    def setUp(self):
        self.detail = {
            "eventName": "CreateAccessKey",
            "eventSource": "iam.amazonaws.com",
            "recipientAccountId": handler.TARGET_ACCOUNT_ID,
            "requestParameters": {
                "userName": handler.TEST_USER,
            },
            "responseElements": {
                "accessKey": {
                    "accessKeyId": "AKIAEXAMPLEKEY123456",
                },
            },
        }

    def test_disposable_username_can_be_configured(self):
        with patch.dict(
            os.environ,
            {"TEST_USER": "self-healing-containment-test"},
        ):
            spec = importlib.util.spec_from_file_location(
                "lambda_function_test_config",
                MODULE_PATH,
            )
            test_handler = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(test_handler)

        self.assertEqual(
            test_handler.TEST_USER,
            "self-healing-containment-test",
        )

    def test_audit_mode_does_not_assume_role_or_deactivate_key(self):
        with (
            patch.object(handler, "ALERT_MODE", "audit"),
            patch.object(handler.sts, "assume_role") as assume_role,
        ):
            result = handler.contain_test_access_key(self.detail)

        self.assertEqual(result, "none")
        assume_role.assert_not_called()

    def test_wrong_event_is_ignored(self):
        detail = dict(self.detail)
        detail["eventName"] = "TagUser"

        with (
            patch.object(handler, "ALERT_MODE", "contain"),
            patch.object(handler.sts, "assume_role") as assume_role,
        ):
            result = handler.contain_test_access_key(detail)

        self.assertEqual(result, "none")
        assume_role.assert_not_called()

    def test_wrong_account_is_ignored(self):
        detail = dict(self.detail)
        detail["recipientAccountId"] = "111122223333"

        with (
            patch.object(handler, "ALERT_MODE", "contain"),
            patch.object(handler.sts, "assume_role") as assume_role,
        ):
            result = handler.contain_test_access_key(detail)

        self.assertEqual(result, "none")
        assume_role.assert_not_called()


    def test_failed_create_access_key_event_is_ignored(self):
        detail = dict(self.detail)
        detail["errorCode"] = "AccessDenied"

        with (
            patch.object(handler, "ALERT_MODE", "contain"),
            patch.object(handler.sts, "assume_role") as assume_role,
        ):
            result = handler.contain_test_access_key(detail)

        self.assertEqual(result, "none")
        assume_role.assert_not_called()

    def test_wrong_username_is_ignored(self):
        detail = dict(self.detail)
        detail["requestParameters"] = {"userName": "another-user"}

        with (
            patch.object(handler, "ALERT_MODE", "contain"),
            patch.object(handler.sts, "assume_role") as assume_role,
        ):
            result = handler.contain_test_access_key(detail)

        self.assertEqual(result, "none")
        assume_role.assert_not_called()

    def test_missing_or_malformed_key_id_is_ignored(self):
        for key_id in (None, "not-an-aws-access-key"):
            with self.subTest(key_id=key_id):
                detail = dict(self.detail)
                detail["responseElements"] = {
                    "accessKey": {"accessKeyId": key_id}
                }

                with (
                    patch.object(handler, "ALERT_MODE", "contain"),
                    patch.object(handler.sts, "assume_role") as assume_role,
                ):
                    result = handler.contain_test_access_key(detail)

                self.assertEqual(result, "none")
                assume_role.assert_not_called()


    def test_valid_event_uses_target_role_and_deactivates_exact_test_key(self):
        fake_credentials = {
            "Credentials": {
                "AccessKeyId": "FAKEACCESSKEY",
                "SecretAccessKey": "fake-secret",
                "SessionToken": "fake-session",
            }
        }
        fake_iam = Mock()
        fake_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAEXAMPLEKEY123456"}
            ]
        }
        fake_iam.update_access_key.return_value = {}

        with (
            patch.object(handler, "ALERT_MODE", "contain"),
            patch.object(handler.sts, "assume_role", return_value=fake_credentials) as assume_role,
            patch.object(handler.boto3, "client", return_value=fake_iam) as client,
        ):
            result = handler.contain_test_access_key(self.detail)

        self.assertEqual(result, "test_access_key_deactivated")
        assume_role.assert_called_once_with(
            RoleArn=handler.TARGET_ROLE_ARN,
            RoleSessionName="IdentitySelfHealingContainment",
            DurationSeconds=900,
        )
        client.assert_called_once()
        fake_iam.list_access_keys.assert_called_once_with(
            UserName=handler.TEST_USER,
        )
        fake_iam.update_access_key.assert_called_once_with(
            UserName=handler.TEST_USER,
            AccessKeyId="AKIAEXAMPLEKEY123456",
            Status="Inactive",
        )

    def test_unowned_key_is_not_deactivated(self):
        fake_credentials = {
            "Credentials": {
                "AccessKeyId": "FAKEACCESSKEY",
                "SecretAccessKey": "fake-secret",
                "SessionToken": "fake-session",
            }
        }
        fake_iam = Mock()
        fake_iam.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAOTHERTESTKEY12345"}
            ]
        }

        with (
            patch.object(handler, "ALERT_MODE", "contain"),
            patch.object(handler.sts, "assume_role", return_value=fake_credentials),
            patch.object(handler.boto3, "client", return_value=fake_iam),
        ):
            result = handler.contain_test_access_key(self.detail)

        self.assertEqual(result, "none")
        fake_iam.list_access_keys.assert_called_once_with(
            UserName=handler.TEST_USER,
        )
        fake_iam.update_access_key.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
