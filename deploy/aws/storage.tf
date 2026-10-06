locals {
  buckets = {
    quarantine = "${var.name_prefix}-quarantine"
    approved   = "${var.name_prefix}-approved"
  }
  sse_algorithm = var.kms_key_arn == null ? "AES256" : "aws:kms"
}

resource "aws_s3_bucket" "files" {
  # checkov:skip=CKV_AWS_144: Cross-region replication doubles storage cost; versioning covers accidental deletes for this project.
  # checkov:skip=CKV_AWS_145: SSE-S3 is the documented cost-free default; set kms_key_arn for SSE-KMS.
  # checkov:skip=CKV2_AWS_62: Quarantine notifies the upload-scan Lambda (upload_scan.tf); approved objects need no event processing.
  for_each = local.buckets
  bucket   = each.value

  tags = { Purpose = each.key }
}

resource "aws_s3_bucket_public_access_block" "files" {
  for_each                = aws_s3_bucket.files
  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Disables ACLs entirely: access is decided only by IAM and bucket policies.
resource "aws_s3_bucket_ownership_controls" "files" {
  for_each = aws_s3_bucket.files
  bucket   = each.value.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "files" {
  for_each = aws_s3_bucket.files
  bucket   = each.value.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "files" {
  for_each = aws_s3_bucket.files
  bucket   = each.value.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = local.sse_algorithm
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

resource "aws_s3_bucket_logging" "files" {
  for_each      = aws_s3_bucket.files
  bucket        = each.value.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "${each.key}/"
}

resource "aws_s3_bucket_lifecycle_configuration" "files" {
  for_each = aws_s3_bucket.files
  bucket   = each.value.id

  rule {
    id     = "expire-old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration {
      noncurrent_days = var.noncurrent_version_retention_days
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }

  dynamic "rule" {
    for_each = each.key == "quarantine" ? [1] : []
    content {
      id     = "expire-unpromoted-uploads"
      status = "Enabled"
      filter {}
      expiration {
        days = var.quarantine_retention_days
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.files]
}

resource "aws_s3_bucket_policy" "files" {
  for_each = aws_s3_bucket.files
  bucket   = each.value.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [each.value.arn, "${each.value.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyOutdatedTls"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [each.value.arn, "${each.value.arn}/*"]
        Condition = { NumericLessThan = { "s3:TlsVersion" = "1.2" } }
      },
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.files]
}

# Server access logs for both file buckets (who requested which object, including pre-signed downloads).
resource "aws_s3_bucket" "access_logs" {
  # checkov:skip=CKV_AWS_18: This is the access-log target; logging it to itself would loop.
  # checkov:skip=CKV_AWS_144: Replication is out of scope (cost).
  # checkov:skip=CKV_AWS_145: S3 server access logging only supports SSE-S3 target buckets.
  # checkov:skip=CKV2_AWS_62: No event processing is needed for access logs.
  bucket = "${var.name_prefix}-access-logs"
  tags   = { Purpose = "access-logs" }
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    id     = "expire-logs"
    status = "Enabled"
    filter {}
    expiration {
      days = 365
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
  depends_on = [aws_s3_bucket_versioning.access_logs]
}

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowS3ServerAccessLogs"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.access_logs.arn}/*"
        Condition = {
          ArnLike      = { "aws:SourceArn" = [for b in aws_s3_bucket.files : b.arn] }
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
  })
  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}
