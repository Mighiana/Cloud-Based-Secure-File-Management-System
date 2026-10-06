output "quarantine_bucket" {
  description = "Storage:QuarantineBucketName"
  value       = aws_s3_bucket.files["quarantine"].id
}

output "approved_bucket" {
  description = "Storage:ApprovedBucketName"
  value       = aws_s3_bucket.files["approved"].id
}

output "server_side_encryption" {
  description = "Storage:ServerSideEncryption"
  value       = local.sse_algorithm
}

output "web_role_arn" {
  value = aws_iam_role.web.arn
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}

output "function_name" {
  value = var.enable_upload_scan_lambda ? aws_lambda_function.scan[0].function_name : null
}
