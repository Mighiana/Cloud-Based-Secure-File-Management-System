variable "region" {
  description = "AWS region of the files bucket."
  type        = string
  default     = "eu-north-1"
}

variable "files_bucket_name" {
  description = "Existing S3 bucket the portal uploads to (Storage:BucketName)."
  type        = string
}

variable "kms_key_arn" {
  description = "Customer-managed KMS key used for SSE-KMS on the bucket, if any. Grants the function kms:Decrypt."
  type        = string
  default     = null
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

variable "log_retention_days" {
  description = "CloudWatch Logs retention for the function."
  type        = number
  default     = 30
}
