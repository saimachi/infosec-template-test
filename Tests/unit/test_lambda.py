import unittest
import uuid

import malware_analysis_lambda.app
from malware_analysis_lambda import app
from unittest.mock import patch

MOCK_BASE_HEADERS = {}


def generate_file_uploaded_to_bucket_event(file_name):
    return \
        {
            "Records": [
                {
                    "eventVersion": "2.0",
                    "eventSource": "aws:s3",
                    "awsRegion": "us-east-2",
                    "eventTime": "1970-01-01T00:00:00.000Z",
                    "eventName": "ObjectCreated:Put",
                    "userIdentity": {
                        "principalId": "EXAMPLE"
                    },
                    "requestParameters": {
                        "sourceIPAddress": "127.0.0.1"
                    },
                    "responseElements": {
                        "x-amz-request-id": "EXAMPLE123456789",
                        "x-amz-id-2": "EXAMPLE123/5678abcdefghijklambdaisawesome/mnopqrstuvwxyzABCDEFGH"
                    },
                    "s3": {
                        "s3SchemaVersion": "1.0",
                        "configurationId": "testConfigRule",
                        "bucket": {
                            "name": "anyrun-lambda-trigger-bucket-dev",
                            "ownerIdentity": {
                                "principalId": "EXAMPLE"
                            },
                            "arn": "arn:aws:s3:::anyrun-lambda-trigger-bucket-dev"
                        },
                        "object": {
                            "key": file_name,
                            "size": 1024,
                            "eTag": "0123456789abcdef0123456789abcdef",
                            "sequencer": "0A1B2C3D4E5F678901"
                        }
                    }
                }
            ]
        }


def mock_populate_any_run_key(secret_name):
    MOCK_BASE_HEADERS['Authorization'] = f'API-Key {"".join(str(uuid.uuid4()).split("-"))}'


def mock_generate_presigned_object_url(bucket, key):
    return f'https://{bucket}.s3.amazonaws.com/{key}?AWSAccessKeyId=ASIA2KL4NTFF2QU6O3S4&Signature' \
           '=y2yljYlfY8GG6uIzVsTIEpfF84c%3D&x-amz-security-token=IQoJb3JpZ2luX2VjEJb%2F%2F%2F%2F%2F%2F%2F%2F%2F' \
           '%2FwEaCXVzLXdlc3QtMSJHMEUCICI0lLw3gbEFiQy' \
           '%2F4lZpuli9azyiMTnj8MKCjcCjj7BVAiEA0s9J6QMq0uVY5FRVdC1Tub6w919PrF6ZRDcB7fSZOukquwII%2F%2F%2F%2F%2F%2F' \
           '%2F%2F%2F%2F%2F%2FARADGgw3MDk0Njc0MTI4MTEiDB407iE4zkLGpSaMYiqPAmBeEuunK8UqusFkvahSm0nXQd' \
           '%2Bu2286X45pttUEQ0dRTdJgup9TYtyssTI3fN0h11j0AEoq7osxe8A45KUxE2FGv0U' \
           '%2BCqS0ThCqSArr0S5PS430yPcVfWjOz9aMBD%2FKDpaUmiYplwvfSKfx57EZZLO2N26N%2BzFDbqqRiciwnlct2Z1r184jK' \
           '%2B3UHygodekZ9hZA2W7iATXCrNTOZkQkBBw43E39fwdGJCv1AGDDFLqmnCKg3mWQkNnVIOpAxeG6%2B9miZMsuoZi' \
           '%2BNygmMGNBOwiQm0ny%2FFH0KWu8dAC1XKjuCCwDUZgKzdkmjOtsSZtdpH239yKqkS8cih%2FjGSuCNu6CqFzy' \
           '%2FcsoToyMTY5WeNwwu7%2BrkQY6mgEFfmHxcd8dbuM8YAtrZYn4K9TCQCWngR%2BoDXeQfsjeDecAtJer76orxbe' \
           '%2BUpL6Ztdo8o7p4BKdy%2FyBOSRAagyFaHUR4CFayrD6HthVG' \
           '%2FSMvGxSi9JbY5LRvSHLkK1hcVvvYSxThPr4lYFQpp2qE3FroQMFkhb5fP5ubPC1TBfwXQFJJK3RmwV39LFQ' \
           '%2F1H6rTighz1f9MsKnt13&Expires=1646980558'


def mock_submit_to_any_run(presigned_url):
    return str(uuid.uuid4())


# Mock context object passed to Function by Lambda runtime
class MockContext:
    pass


@patch('malware_analysis_lambda.app.BASE_HEADERS', MOCK_BASE_HEADERS)
@patch('malware_analysis_lambda.app.API_BASE_PATH', 'https://api.any.run/v1')
@patch('malware_analysis_lambda.app.generate_presigned_object_url', mock_generate_presigned_object_url)
@patch('malware_analysis_lambda.app.populate_any_run_key', mock_populate_any_run_key)
class AnyRunSubmissionLambdaTest(unittest.TestCase):
    def test_any_run_payload(self):
        payload = app.generate_any_run_payload(generate_file_uploaded_to_bucket_event('eicar.com'))
        self.assertEqual(payload['obj_type'], 'download')
        expected_url = mock_generate_presigned_object_url('anyrun-lambda-trigger-bucket-dev', 'eicar.com')
        self.assertEqual(payload['obj_url'], expected_url)


if __name__ == '__main__':
    unittest.main()
