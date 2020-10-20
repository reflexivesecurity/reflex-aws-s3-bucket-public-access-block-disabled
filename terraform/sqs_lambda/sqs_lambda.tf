module "sqs_lambda" {
  source = "git::https://github.com/reflexivesecurity/reflex-engine.git//modules/sqs_lambda?ref=v2.1.2"

  cloudwatch_event_rule_id  = var.cloudwatch_event_rule_id
  cloudwatch_event_rule_arn = var.cloudwatch_event_rule_arn
  function_name             = "S3BucketPublicAccessBlockDisabled"
  package_location          = var.package_location
  handler                   = "s3_bucket_public_access_block_disabled.lambda_handler"
  lambda_runtime            = "python3.7"
  environment_variable_map = {
    SNS_TOPIC = var.sns_topic_arn,

  }

  queue_name    = "S3BucketPublicAccessBlockDisabled"
  delay_seconds = 0

  target_id = "S3BucketPublicAccessBlockDisabled"

  sns_topic_arn  = var.sns_topic_arn
  sqs_kms_key_id = var.reflex_kms_key_id
}
