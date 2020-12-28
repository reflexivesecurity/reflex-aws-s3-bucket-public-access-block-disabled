""" Module for detecting S3BucketPublicAccessBlockDisabled """

import json
import os

import boto3
from reflex_core import AWSRule, subscription_confirmation


class S3BucketPublicAccessBlockDisabled(AWSRule):
    """ AWS rule for detecting removal of S3 bucket public access blocks  """

    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ To be implemented by every rule """
        self.raw_event = event
        self.bucket_name = event["detail"]["requestParameters"]["bucketName"]
        self.block_configuration = event["detail"]["requestParameters"][
            "PublicAccessBlockConfiguration"
        ]

    def resource_compliant(self):
        """ True if all blocks are set to True."""
        return self.all_s3_bucket_public_access_block_disableds_true()

    def all_s3_bucket_public_access_block_disableds_true(self):
        """Iterates over blocks and checks if True."""
        del self.block_configuration["xmlns"]
        for block in self.block_configuration:
            if not self.block_configuration[block]:
                return False
        return True

    def remediate(self):
        """ Fix the non-compliant resource """
        self.set_all_s3_bucket_public_access_blocks_true()

    def set_all_s3_bucket_public_access_blocks_true(self):
        self.client.put_public_access_block(
            Bucket=self.bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return (
            f"The public access block for the bucket {self.bucket_name}"
            f" was changed to {self.block_configuration}"
        )


def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    event_payload = json.loads(event["Records"][0]["body"])
    if subscription_confirmation.is_subscription_confirmation(event_payload):
        subscription_confirmation.confirm_subscription(event_payload)
        return
    access_block_rule = S3BucketPublicAccessBlockDisabled(event_payload)
    access_block_rule.run_compliance_rule()
