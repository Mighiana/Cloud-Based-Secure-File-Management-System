# upload-scan Lambda

S3-triggered function that checks every new object in the portal's **quarantine** bucket, tags
it with the result and sends an e-mail alert through SNS.

It is an independent second signal, not the approval step: the portal's own validation worker
decides `Approved / Rejected / Quarantined` and is the only thing that copies objects into the
approved bucket. If the worker promotes and deletes an object before the Lambda reads it, the
Lambda skips it (no alert).

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

- object tags `scan-status=clean|rejected|error`, `scan-reason=<why>` and `scan-etag=<ETag>`
- SNS message with subject `Secure File Upload: Scan Complete` or `... Scan Failed` and the
  file, bucket, size, type, result and timestamp
- one JSON log line per object in CloudWatch Logs

Objects deleted before the scan runs are skipped. Duplicate S3 events for an object version that
already carries a matching `scan-etag` are skipped, so a redelivered event does not send a second
alert; a new version (different ETag) is scanned again. Other AWS errors tag the object
`scan-status=error` (best effort) and are re-raised so Lambda's asynchronous retries apply;
events that still fail go to the SQS dead-letter queue. Log lines carry the request ID.

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `SNS_TOPIC_ARN` | empty (no alert) | set by Terraform |
| `MAX_FILE_SIZE_MB` | `50` | keep in sync with the portal's `Upload:MaxFileSizeMB` |
| `ALLOWED_EXTENSIONS` | `.pdf,.docx,.xlsx,.txt,.png,.jpg,.jpeg` | keep in sync with `Upload:AllowedExtensions` |
| `TAG_OBJECTS` | `true` | |

## Deploy (Terraform)

The function is part of the root module in [`deploy/aws`](../../deploy/aws), which also creates
the quarantine/approved buckets and IAM roles:

```bash
cd deploy/aws
cp terraform.tfvars.example terraform.tfvars   # name prefix, region, alert e-mails, optional KMS key
terraform init
terraform plan
terraform apply
```

Set `enable_upload_scan_lambda = false` to deploy the buckets and roles without it.

Each address in `alert_emails` receives an SNS confirmation e-mail and must confirm it before
alerts arrive. If the bucket uses SSE-KMS with a customer-managed key, set `kms_key_arn` so the
function can decrypt objects (and allow the role in the key policy if it doesn't delegate to IAM).

In the Docker demo (`docker compose up`) LocalStack deploys the same handler and wires it to the
quarantine bucket; alerts land in the `upload-alerts-inbox` SQS queue instead of e-mail.

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
needed (29 tests). `make check` / CI also run `terraform fmt`, `validate`, `test`, TFLint and
Checkov on `deploy/aws`.
