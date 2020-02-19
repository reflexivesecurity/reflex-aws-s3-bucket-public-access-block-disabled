""" Module for detecting PublicAccessBlockRule """

import json
import os

import boto3
from reflex_core import AWSRule


class PublicAccessBlockRule(AWSRule):
    """ AWS rule for detecting removal of S3 bucket public access blocks  """

    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ To be implemented by every rule """
        self.raw_event = event
        self.block_configuration = (event["detail"]
                                    ["requestParameters"]
                                    ["PublicAccessBlockConfiguration"])

    def resource_compliant(self):
        """ True if all blocks are set to True."""
        return self.all_public_access_blocks_true()

    def all_public_access_blocks_true(self):
        """Iterates over blocks and checks if True."""
        del self.block_configuration['xmlns']
        for block in self.block_configuration:
            if not self.block_configuration[block]:
                return False
        return True

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return "The public access block was changed to" \
               f"{self.block_configuration}, raw event: {self.raw_event} "

    def remediate(self):
        """ Since this is a detective control, no remediation action is taken """
        return

def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    access_block_rule = PublicAccessBlockRule(json.loads(event["Records"][0]["body"]))
    access_block_rule.run_compliance_rule()
