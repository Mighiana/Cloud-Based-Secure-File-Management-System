#!/bin/sh
# LocalStack init hook for the local demo:
#  - "secure-files": application bucket (public access blocked, default SSE-S3 encryption)
#  - "demo-cloudtrail": SAMPLE CloudTrail log files (synthetic, account 000000000000) so the
#    CloudTrail viewer can be exercised without a real AWS trail.
set -e
awslocal s3 mb s3://secure-files || true
awslocal s3api put-public-access-block --bucket secure-files \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
awslocal s3api put-bucket-encryption --bucket secure-files \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'

awslocal s3 mb s3://demo-cloudtrail || true
python3 - <<'PY'
import gzip, json, datetime, subprocess
acct = "000000000000"
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
role = {"type": "AssumedRole", "arn": f"arn:aws:sts::{acct}:assumed-role/secure-portal-app/i-0demo", "accountId": acct}
def event(minutes_ago, name, key, error=None):
    e = {"eventVersion": "1.09", "eventTime": (now - datetime.timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z"),
         "eventSource": "s3.amazonaws.com", "eventName": name, "awsRegion": "eu-central-1", "sourceIPAddress": "10.0.1.25",
         "userIdentity": role, "requestParameters": {"bucketName": "secure-files", "key": key}, "readOnly": name.startswith(("Get", "List")),
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
