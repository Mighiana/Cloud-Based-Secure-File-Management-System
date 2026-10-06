# Runs entirely offline with a mocked AWS provider: no credentials, no real resources.
mock_provider "aws" {
  mock_data "aws_caller_identity" {
    defaults = { account_id = "111122223333" }
  }
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::mock-bucket" }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/mock" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:eu-central-1:111122223333:mock" }
  }
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:eu-central-1:111122223333:mock" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:eu-central-1:111122223333:log-group:mock" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:eu-central-1:111122223333:function:mock" }
  }
}

variables {
  name_prefix = "test-secure-files"
}

run "buckets_are_private_versioned_and_encrypted_with_sse_s3" {
  command = apply

  assert {
    condition     = toset(keys(aws_s3_bucket.files)) == toset(["quarantine", "approved"])
    error_message = "Expected separate quarantine and approved buckets."
  }
  assert {
    condition = alltrue([for p in concat(values(aws_s3_bucket_public_access_block.files), [aws_s3_bucket_public_access_block.access_logs]) :
    p.block_public_acls && p.block_public_policy && p.ignore_public_acls && p.restrict_public_buckets])
    error_message = "Every bucket must block all public access."
  }
  assert {
    condition     = alltrue([for o in values(aws_s3_bucket_ownership_controls.files) : o.rule[0].object_ownership == "BucketOwnerEnforced"])
    error_message = "ACLs must be disabled (BucketOwnerEnforced)."
  }
  assert {
    condition     = alltrue([for v in values(aws_s3_bucket_versioning.files) : v.versioning_configuration[0].status == "Enabled"])
    error_message = "Versioning must be enabled."
  }
  assert {
    condition = alltrue([for e in values(aws_s3_bucket_server_side_encryption_configuration.files) :
    one(one(e.rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"])
    error_message = "Default encryption must be SSE-S3 when no KMS key is given."
  }
}

run "bucket_policies_deny_non_tls_access" {
  command = apply

  assert {
    condition = alltrue([for p in values(aws_s3_bucket_policy.files) : anytrue([for s in jsondecode(p.policy).Statement :
    s.Effect == "Deny" && s.Condition == { Bool = { "aws:SecureTransport" = "false" } }])])
    error_message = "Each file bucket policy must deny requests without TLS."
  }
}

run "iam_policies_are_least_privilege" {
  command = apply

  assert {
    condition = alltrue(flatten([for p in [aws_iam_role_policy.web.policy, aws_iam_role_policy.web_validation_worker.policy, aws_iam_role_policy.function[0].policy] : [
      for s in jsondecode(p).Statement : [
        for a in flatten([s.Action]) : a != "*" && !endswith(a, ":*")
    ]]]))
    error_message = "No IAM statement may grant '*' or 'service:*' actions."
  }
  assert {
    condition = alltrue(flatten([for p in [aws_iam_role_policy.web.policy, aws_iam_role_policy.web_validation_worker.policy, aws_iam_role_policy.function[0].policy] : [
    for s in jsondecode(p).Statement : s.Resource != "*"]]))
    error_message = "No IAM statement may target every resource."
  }
  assert {
    condition = !anytrue(flatten([for s in jsondecode(aws_iam_role_policy.function[0].policy).Statement :
    [for r in flatten([s.Resource]) : strcontains(r, aws_s3_bucket.files["approved"].bucket)]]))
    error_message = "The Lambda role must have no access to the approved bucket."
  }
}

run "optional_sse_kms" {
  command = apply

  variables {
    kms_key_arn = "arn:aws:kms:eu-central-1:111122223333:key/11111111-2222-3333-4444-555555555555"
  }

  assert {
    condition = alltrue([for e in values(aws_s3_bucket_server_side_encryption_configuration.files) :
    one(one(e.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"])
    error_message = "Setting kms_key_arn must switch to SSE-KMS."
  }
  assert {
    condition     = anytrue([for s in jsondecode(aws_iam_role_policy.web.policy).Statement : s.Sid == "UseFileEncryptionKey"])
    error_message = "The web role needs the KMS key when SSE-KMS is used."
  }
}

run "lambda_can_be_disabled" {
  command = apply

  variables {
    enable_upload_scan_lambda = false
  }

  assert {
    condition     = length(aws_lambda_function.scan) == 0 && length(aws_s3_bucket_notification.quarantine) == 0
    error_message = "Disabling the Lambda must remove the function and its trigger."
  }
}

run "rejects_invalid_bucket_prefix" {
  command = plan

  variables {
    name_prefix = "Bad_Prefix"
  }
  expect_failures = [var.name_prefix]
}
