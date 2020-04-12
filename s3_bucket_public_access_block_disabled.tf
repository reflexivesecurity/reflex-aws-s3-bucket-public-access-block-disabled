module "disable_s3_bucket_public_access_block_disabled" {
  source           = "git::https://github.com/cloudmitigator/reflex-engine.git//modules/cwe_lambda?ref=v0.5.7"
  rule_name        = "S3BucketPublicAccessBlockDisabled"
  rule_description = "Rule to detect a change in public access block configuration for an S3 bucket"

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
      "PutBucketPublicAccessBlock"
    ]
  }
}
PATTERN

  function_name            = "S3BucketPublicAccessBlockDisabled"
  source_code_dir          = "${path.module}/source"
  handler                  = "s3_bucket_public_access_block_disabled.lambda_handler"
  lambda_runtime           = "python3.7"
  environment_variable_map = { SNS_TOPIC = var.sns_topic_arn }
  custom_lambda_policy     = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:ListBuckets"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF



  queue_name    = "S3BucketPublicAccessBlockDisabled"
  delay_seconds = 0

  target_id = "S3BucketPublicAccessBlockDisabled"

  sns_topic_arn  = var.sns_topic_arn
  sqs_kms_key_id = var.reflex_kms_key_id
}
