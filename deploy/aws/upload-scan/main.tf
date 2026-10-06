data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

data "aws_s3_bucket" "files" {
  bucket = var.files_bucket_name
}

data "archive_file" "function" {
  type        = "zip"
  source_file = "${path.module}/../../../lambda/upload-scan/handler.py"
  output_path = "${path.module}/build/upload-scan.zip"
}

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

resource "aws_cloudwatch_log_group" "function" {
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_retention_days
}

data "aws_iam_policy_document" "assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "function" {
  name               = "${var.function_name}-role"
  assume_role_policy = data.aws_iam_policy_document.assume.json
}

data "aws_iam_policy_document" "function" {
  statement {
    sid       = "WriteOwnLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.function.arn}:*"]
  }

  statement {
    sid       = "ReadAndTagUploads"
    actions   = ["s3:GetObject", "s3:PutObjectTagging"]
    resources = ["${data.aws_s3_bucket.files.arn}/*"]
  }

  statement {
    sid       = "PublishScanResults"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  dynamic "statement" {
    for_each = var.kms_key_arn == null ? [] : [var.kms_key_arn]
    content {
      sid       = "DecryptSseKmsObjects"
      actions   = ["kms:Decrypt"]
      resources = [statement.value]
    }
  }
}

resource "aws_iam_role_policy" "function" {
  name   = "${var.function_name}-policy"
  role   = aws_iam_role.function.id
  policy = data.aws_iam_policy_document.function.json
}

resource "aws_lambda_function" "scan" {
  function_name    = var.function_name
  description      = "Post-upload file checks (size, extension, signature) with SNS alerts."
  role             = aws_iam_role.function.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.function.output_path
  source_code_hash = data.archive_file.function.output_base64sha256
  timeout          = 30
  memory_size      = 128

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

resource "aws_lambda_permission" "s3" {
  statement_id   = "AllowS3Invoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.scan.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = data.aws_s3_bucket.files.arn
  source_account = data.aws_caller_identity.current.account_id
}

# Replaces any existing notification configuration on the bucket.
resource "aws_s3_bucket_notification" "uploads" {
  bucket = data.aws_s3_bucket.files.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.scan.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.s3]
}
