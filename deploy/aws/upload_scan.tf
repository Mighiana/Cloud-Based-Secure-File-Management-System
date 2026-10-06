# 2026 reconstruction of the 2025 console-built S3 -> Lambda -> SNS upload alert.
# An independent second check on the quarantine bucket: tags objects and sends alerts; the portal's
# own validation worker decides approval.

locals {
  lambda_count = var.enable_upload_scan_lambda ? 1 : 0
}

data "archive_file" "function" {
  count       = local.lambda_count
  type        = "zip"
  source_file = "${path.module}/../../lambda/upload-scan/handler.py"
  output_path = "${path.module}/build/upload-scan.zip"
}

# AWS-managed SNS key: encrypted at rest with no KMS key cost.
resource "aws_sns_topic" "alerts" {
  name              = var.topic_name
  kms_master_key_id = "alias/aws/sns"
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.alert_emails)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}

# Events that still fail after Lambda's async retries land here instead of being dropped.
resource "aws_sqs_queue" "scan_dlq" {
  count                     = local.lambda_count
  name                      = "${var.function_name}-dlq"
  sqs_managed_sse_enabled   = true
  message_retention_seconds = 1209600
}

resource "aws_cloudwatch_log_group" "function" {
  # checkov:skip=CKV_AWS_158: Log encryption uses the CloudWatch default; a CMK adds cost.
  # checkov:skip=CKV_AWS_338: 30-day retention is a deliberate cost choice (configurable).
  count             = local.lambda_count
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_retention_days
}

resource "aws_iam_role" "function" {
  count = local.lambda_count
  name  = "${var.function_name}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "function" {
  count = local.lambda_count
  name  = "${var.function_name}-policy"
  role  = aws_iam_role.function[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = concat([
      {
        Sid      = "WriteOwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.function[0].arn}:*"
      },
      {
        Sid      = "ReadAndTagQuarantinedUploads"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectTagging", "s3:PutObjectTagging"]
        Resource = "${local.quarantine_arn}/*"
      },
      {
        Sid      = "PublishScanResults"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = aws_sns_topic.alerts.arn
      },
      {
        Sid      = "DeadLetterFailedEvents"
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.scan_dlq[0].arn
      },
      ], var.kms_key_arn == null ? [] : [{
        Sid      = "DecryptSseKmsObjects"
        Effect   = "Allow"
        Action   = ["kms:Decrypt"]
        Resource = var.kms_key_arn
    }])
  })
}

resource "aws_lambda_function" "scan" {
  # checkov:skip=CKV_AWS_117: The function only calls S3/SNS public endpoints; a VPC would need NAT or endpoints (cost).
  # checkov:skip=CKV_AWS_173: Environment variables hold no secrets (topic ARN, limits).
  # checkov:skip=CKV_AWS_272: Code signing needs AWS Signer profiles; out of scope for this project.
  count                          = local.lambda_count
  function_name                  = var.function_name
  description                    = "Post-upload file checks (size, extension, signature) with SNS alerts."
  role                           = aws_iam_role.function[0].arn
  runtime                        = "python3.12"
  handler                        = "handler.lambda_handler"
  filename                       = data.archive_file.function[0].output_path
  source_code_hash               = data.archive_file.function[0].output_base64sha256
  timeout                        = 30
  memory_size                    = 128
  reserved_concurrent_executions = var.lambda_reserved_concurrency

  tracing_config {
    mode = "PassThrough"
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.scan_dlq[0].arn
  }

  environment {
    variables = {
      SNS_TOPIC_ARN      = aws_sns_topic.alerts.arn
      MAX_FILE_SIZE_MB   = tostring(var.max_file_size_mb)
      ALLOWED_EXTENSIONS = join(",", var.allowed_extensions)
      TAG_OBJECTS        = "true"
    }
  }

  depends_on = [aws_cloudwatch_log_group.function, aws_iam_role_policy.function]
}

resource "aws_lambda_function_event_invoke_config" "scan" {
  count                        = local.lambda_count
  function_name                = aws_lambda_function.scan[0].function_name
  maximum_retry_attempts       = 2
  maximum_event_age_in_seconds = 3600
}

resource "aws_lambda_permission" "s3" {
  count          = local.lambda_count
  statement_id   = "AllowS3Invoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.scan[0].function_name
  principal      = "s3.amazonaws.com"
  source_arn     = local.quarantine_arn
  source_account = data.aws_caller_identity.current.account_id
}

resource "aws_s3_bucket_notification" "quarantine" {
  count  = local.lambda_count
  bucket = aws_s3_bucket.files["quarantine"].id

  lambda_function {
    lambda_function_arn = aws_lambda_function.scan[0].arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.s3]
}
