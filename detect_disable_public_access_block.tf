provider "aws" {
  region = "us-east-1"
}

module "detect_disable_public_access_block" {
  source           = "git@github.com:cloudmitigator/reflex.git//modules/cwe_lambda"
  rule_name        = "DetectDisablePublicAccessBlock"
  rule_description = "Rule to detect a change in public access block configuration"

  event_pattern = <<PATTERN
{
  "detail-type": [
    "AWS API Call via CloudTrail"
  ],
  "source": [
    "aws.s3"
  ],
  "detail": {
    "eventSource": [
      "s3.amazonaws.com"
    ],
    "eventName": [
      "PutAccountPublicAccessBlock"
      "PutBucketPublicAccessBlock"
    ]
  }
}
PATTERN

  function_name            = "DetectDisablePublicAccessBlock"
  source_code_dir          = "${path.module}/source"
  handler                  = "public_access_block.lambda_handler"
  lambda_runtime           = "python3.7"
  environment_variable_map = { SNS_TOPIC = "DetectDisablePublicAccessBlock" }
  custom_lambda_policy     = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetEncryptionConfiguration",
        "s3:PutEncryptionConfiguration"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF



  queue_name    = "DetectDisablePublicAccessBlock"
  delay_seconds = 60

  target_id = "DetectDisablePublicAccessBlock"

  topic_name = "DetectDisablePublicAccessBlock"
  email      = var.email
}
