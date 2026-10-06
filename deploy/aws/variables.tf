variable "region" {
  description = "AWS region for the buckets, Lambda and SNS topic."
  type        = string
  default     = "eu-central-1"
}

variable "name_prefix" {
  description = "Globally unique prefix for bucket names, e.g. \"acme-secure-files\". Creates <prefix>-quarantine, <prefix>-approved and <prefix>-access-logs."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{2,40}[a-z0-9]$", var.name_prefix))
    error_message = "name_prefix must be 4-42 lowercase letters, digits or hyphens."
  }
}

variable "kms_key_arn" {
  description = "Optional customer-managed KMS key for SSE-KMS. Null (default) uses SSE-S3 (AES256), which has no KMS cost."
  type        = string
  default     = null
}

variable "quarantine_retention_days" {
  description = "Objects left in the quarantine bucket (rejected or quarantined uploads) expire after this many days."
  type        = number
  default     = 30
}

variable "noncurrent_version_retention_days" {
  description = "Days to keep previous object versions (recovery from accidental delete/overwrite) before expiry."
  type        = number
  default     = 30
}

variable "cloudtrail_bucket_name" {
  description = "Optional existing bucket holding CloudTrail logs that the portal's admin log viewer reads. Null grants no CloudTrail access."
  type        = string
  default     = null
}

variable "app_trusted_services" {
  description = "AWS service principals allowed to assume the portal role (where the app runs)."
  type        = list(string)
  default     = ["ecs-tasks.amazonaws.com"]
}

variable "enable_upload_scan_lambda" {
  description = "Deploy the reconstructed upload-scan Lambda (independent file-hygiene check + SNS alert) on the quarantine bucket."
  type        = bool
  default     = true
}

variable "alert_emails" {
  description = "E-mail addresses subscribed to scan alerts. Each must confirm the SNS subscription."
  type        = list(string)
  default     = []
}

variable "topic_name" {
  description = "SNS topic for scan results."
  type        = string
  default     = "FileUploadAlerts"
}

variable "function_name" {
  description = "Lambda function name."
  type        = string
  default     = "secure-file-upload-scan"
}

variable "max_file_size_mb" {
  description = "Should match Upload:MaxFileSizeMB in the portal."
  type        = number
  default     = 50
}

variable "allowed_extensions" {
  description = "Should match Upload:AllowedExtensions in the portal."
  type        = list(string)
  default     = [".pdf", ".docx", ".xlsx", ".txt", ".png", ".jpg", ".jpeg"]
}

variable "lambda_reserved_concurrency" {
  description = "Upper bound on concurrent scans, limiting cost and blast radius of an upload flood."
  type        = number
  default     = 5
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the function."
  type        = number
  default     = 30
}
