#!/bin/sh
# LocalStack init hook for the local demo (community edition, no AWS account):
#  - secure-files-quarantine / secure-files-approved: private buckets (public access blocked,
#    ACLs disabled, versioning, default SSE-S3) mirroring deploy/aws/secure-storage
#  - FileUploadAlerts SNS topic with an SQS "inbox" so alerts can be read locally
#  - optional upload-scan Lambda on the quarantine bucket (UPLOAD_SCAN_LAMBDA=true)
#  - demo-cloudtrail: SAMPLE CloudTrail log files (synthetic, account 000000000000) so the
#    CloudTrail viewer can be exercised without a real AWS trail.
set -eu
REGION=us-east-1

for b in secure-files-quarantine secure-files-approved; do
  awslocal s3 mb "s3://$b" || true
  awslocal s3api put-public-access-block --bucket "$b" \
    --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  awslocal s3api put-bucket-ownership-controls --bucket "$b" \
    --ownership-controls 'Rules=[{ObjectOwnership=BucketOwnerEnforced}]'
  awslocal s3api put-bucket-versioning --bucket "$b" --versioning-configuration Status=Enabled
  awslocal s3api put-bucket-encryption --bucket "$b" \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
done

TOPIC_ARN=$(awslocal sns create-topic --name FileUploadAlerts --query TopicArn --output text)
QUEUE_URL=$(awslocal sqs create-queue --queue-name upload-alerts-inbox --query QueueUrl --output text)
QUEUE_ARN=$(awslocal sqs get-queue-attributes --queue-url "$QUEUE_URL" --attribute-names QueueArn --query Attributes.QueueArn --output text)
awslocal sns subscribe --topic-arn "$TOPIC_ARN" --protocol sqs --notification-endpoint "$QUEUE_ARN" >/dev/null

if [ "${UPLOAD_SCAN_LAMBDA:-true}" = "true" ]; then
  python3 -c "import zipfile; z = zipfile.ZipFile('/tmp/upload-scan.zip', 'w'); z.write('/opt/upload-scan/handler.py', 'handler.py'); z.close()"
  awslocal lambda create-function --function-name secure-file-upload-scan \
    --runtime python3.12 --handler handler.lambda_handler --timeout 30 \
    --role arn:aws:iam::000000000000:role/upload-scan --zip-file fileb:///tmp/upload-scan.zip \
    --environment "Variables={SNS_TOPIC_ARN=$TOPIC_ARN,TAG_OBJECTS=true,MAX_FILE_SIZE_MB=50}" >/dev/null
  awslocal lambda wait function-active-v2 --function-name secure-file-upload-scan
  awslocal lambda add-permission --function-name secure-file-upload-scan --statement-id AllowS3Invoke \
    --action lambda:InvokeFunction --principal s3.amazonaws.com \
    --source-arn arn:aws:s3:::secure-files-quarantine >/dev/null
  awslocal s3api put-bucket-notification-configuration --bucket secure-files-quarantine \
    --notification-configuration "{\"LambdaFunctionConfigurations\":[{\"LambdaFunctionArn\":\"arn:aws:lambda:$REGION:000000000000:function:secure-file-upload-scan\",\"Events\":[\"s3:ObjectCreated:*\"]}]}"
fi

awslocal s3 mb s3://demo-cloudtrail || true
python3 - <<'PY'
import gzip, json, datetime, subprocess
acct = "000000000000"
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
role = {"type": "AssumedRole", "arn": f"arn:aws:sts::{acct}:assumed-role/secure-portal-app/i-0demo", "accountId": acct}
def event(minutes_ago, name, key, error=None):
    e = {"eventVersion": "1.09", "eventTime": (now - datetime.timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z"),
         "eventSource": "s3.amazonaws.com", "eventName": name, "awsRegion": "eu-central-1", "sourceIPAddress": "10.0.1.25",
         "userIdentity": role, "requestParameters": {"bucketName": "secure-files-approved", "key": key}, "readOnly": name.startswith(("Get", "List")),
         "eventType": "AwsApiCall", "managementEvent": False, "recipientAccountId": acct}
    if error:
        e["errorCode"], e["errorMessage"] = error, "Access Denied"
    return e
batches = [
    [event(50, "PutObject", "3f1c0e2a.pdf"), event(48, "GetObject", "3f1c0e2a.pdf")],
    [event(30, "PutObject", "9b7d41aa.xlsx"), event(25, "DeleteObject", "51c2f0d9.png")],
    [event(10, "GetObject", "secret/../../etc", "AccessDenied"), event(5, "ListObjects", "")],
]
for i, records in enumerate(batches):
    t = now - datetime.timedelta(minutes=50 - i * 20)
    key = f"AWSLogs/{acct}/CloudTrail/eu-central-1/{t:%Y/%m/%d}/{acct}_CloudTrail_eu-central-1_{t:%Y%m%dT%H%M}Z_sample{i}.json.gz"
    path = f"/tmp/sample{i}.json.gz"
    with gzip.open(path, "wt") as f:
        json.dump({"Records": records}, f)
    subprocess.run(["awslocal", "s3", "cp", path, f"s3://demo-cloudtrail/{key}"], check=True)
PY

touch /tmp/init-aws.done
