data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

locals {
  quarantine_arn = "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.files["quarantine"].bucket}"
  approved_arn   = "arn:${data.aws_partition.current.partition}:s3:::${aws_s3_bucket.files["approved"].bucket}"
  kms_statements = var.kms_key_arn == null ? [] : [{
    Sid      = "UseFileEncryptionKey"
    Effect   = "Allow"
    Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
    Resource = var.kms_key_arn
  }]

  # Web app: write new uploads to quarantine, sign downloads from approved, delete either copy.
  web_statements = concat([
    {
      Sid      = "WriteUploadsToQuarantine"
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:DeleteObject"]
      Resource = "${local.quarantine_arn}/*"
    },
    {
      Sid      = "ServeAndDeleteApprovedFiles"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:DeleteObject"]
      Resource = "${local.approved_arn}/*"
    },
    ], var.cloudtrail_bucket_name == null ? [] : [
    {
      Sid      = "ListCloudTrailLogs"
      Effect   = "Allow"
      Action   = ["s3:ListBucket"]
      Resource = "arn:${data.aws_partition.current.partition}:s3:::${var.cloudtrail_bucket_name}"
    },
    {
      Sid      = "ReadCloudTrailLogs"
      Effect   = "Allow"
      Action   = ["s3:GetObject"]
      Resource = "arn:${data.aws_partition.current.partition}:s3:::${var.cloudtrail_bucket_name}/*"
    },
  ], local.kms_statements)

  # Validation worker (runs inside the web process, so it shares the web role): read from quarantine,
  # copy approved objects across, remove the quarantine copy.
  validator_statements = concat([
    {
      Sid      = "ReadAndRemoveQuarantine"
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:GetObjectTagging", "s3:DeleteObject"]
      Resource = "${local.quarantine_arn}/*"
    },
    {
      Sid      = "PromoteToApproved"
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:PutObjectTagging"]
      Resource = "${local.approved_arn}/*"
    },
  ], local.kms_statements)

  app_assume_role = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = var.app_trusted_services }
    }]
  })
}

resource "aws_iam_role" "web" {
  name               = "${var.name_prefix}-web"
  description        = "Secure file portal web application"
  assume_role_policy = local.app_assume_role
}

resource "aws_iam_role_policy" "web" {
  name   = "file-portal-web"
  role   = aws_iam_role.web.id
  policy = jsonencode({ Version = "2012-10-17", Statement = local.web_statements })
}

resource "aws_iam_role_policy" "web_validation_worker" {
  name   = "file-portal-validation-worker"
  role   = aws_iam_role.web.id
  policy = jsonencode({ Version = "2012-10-17", Statement = local.validator_statements })
}
