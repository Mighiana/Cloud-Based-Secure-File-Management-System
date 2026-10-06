# upload-scan Lambda

S3-triggered function that checks every new object in the portal's files bucket, tags it with
the result and sends an e-mail alert through SNS.

**Provenance.** The 2025 coursework deployment had a console-built Lambda + SNS pipeline that
sent "Secure File Upload: Scan Complete / Scan Failed" e-mails (see the screenshot in the
[main README](../../README.md#2025-upload-alerts-aws-lambda--sns)). Its source was never
committed; this directory is a **2026 reconstruction** of that function as code.

## What it checks

| Check | Rejected when |
|---|---|
| Size | object is empty or larger than `MAX_FILE_SIZE_MB` |
| Extension | not in `ALLOWED_EXTENSIONS` |
| Signature | first bytes don't match the extension: `%PDF-` (.pdf), PNG magic (.png), `FF D8 FF` (.jpg/.jpeg), ZIP `PK\x03\x04` (.docx/.xlsx), NUL bytes in a .txt |

Only the first 8 KB are read (ranged `GetObject`); the size comes from S3. These are
file-hygiene checks, **not malware or content scanning**.

Results:

- object tags `scan-status=clean|rejected` and `scan-reason=<why>`
- SNS message with subject `Secure File Upload: Scan Complete` or `... Scan Failed` and the
  file, bucket, size, type, result and timestamp
- one JSON log line per object in CloudWatch Logs

Objects deleted before the scan runs are skipped. Other AWS errors are raised so Lambda's
asynchronous retries apply.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `SNS_TOPIC_ARN` | empty (no alert) | set by Terraform |
| `MAX_FILE_SIZE_MB` | `50` | keep in sync with the portal's `Upload:MaxFileSizeMB` |
| `ALLOWED_EXTENSIONS` | `.pdf,.docx,.xlsx,.txt,.png,.jpg,.jpeg` | keep in sync with `Upload:AllowedExtensions` |
| `TAG_OBJECTS` | `true` | |

## Deploy (Terraform)

```bash
cd deploy/aws/upload-scan
cp terraform.tfvars.example terraform.tfvars   # bucket name, region, alert e-mails, optional KMS key
terraform init
terraform plan
terraform apply
```

Each address in `alert_emails` receives an SNS confirmation e-mail and must confirm it before
alerts arrive. `aws_s3_bucket_notification` **replaces** any existing notification configuration
on the bucket. If the bucket uses SSE-KMS with a customer-managed key, set `kms_key_arn` so the
function can decrypt objects (and allow the role in the key policy if it doesn't delegate to IAM).

This code has been verified with unit tests and against LocalStack, but has not been deployed
to a real AWS account from this repository.

## Tests

```bash
cd lambda/upload-scan
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q tests
```

The tests use [moto](https://github.com/getmoto/moto) for S3/SNS/SQS, so no AWS account is
needed. CI also runs `terraform fmt -check` and `terraform validate` on the Terraform module.
