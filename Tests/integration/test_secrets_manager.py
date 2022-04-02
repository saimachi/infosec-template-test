from botocore.exceptions import ClientError
import unittest
from unittest.mock import patch
from malware_analysis_lambda import app

MOCK_BASE_HEADERS = {}


class SecretsManagerTest(unittest.TestCase):
    VALID_SECRET_NAME = 'dev/AnyRunLambda/AnyRunSecret'

    @patch('malware_analysis_lambda.app.BASE_HEADERS', MOCK_BASE_HEADERS)
    def test_secrets_manager_valid(self):
        app.populate_any_run_key(SecretsManagerTest.VALID_SECRET_NAME)
        self.assertTrue('Authorization' in MOCK_BASE_HEADERS)

    @patch('malware_analysis_lambda.app.BASE_HEADERS', MOCK_BASE_HEADERS)
    def test_secrets_manager_invalid(self):
        with self.assertRaises(ClientError):
            app.populate_any_run_key('false/secret')


if __name__ == '__main__':
    unittest.main()
