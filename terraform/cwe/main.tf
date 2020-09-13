module "cwe" {
  source      = "git::https://github.com/reflexivesecurity/reflex-engine.git//modules/cwe?ref=v2.1.0"
  name        = "S3BucketPublicAccessBlockDisabled"
  description = "Rule to detect a change in public access block configuration for an S3 bucket"

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

}
