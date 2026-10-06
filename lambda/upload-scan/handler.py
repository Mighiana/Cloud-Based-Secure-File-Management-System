"""S3 upload scan: basic post-upload checks, object tagging and SNS e-mail alerts.

2026 reconstruction of the console-built Lambda from the 2025 coursework deployment.
These are file-hygiene checks (size, extension, file signature), not malware scanning.

S3 delivers events at least once, so processing is idempotent: the object's ETag is recorded in a
scan-etag tag and a repeated event for the same object version is skipped without a second alert.
"""

import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import unquote_plus

import boto3
from botocore.exceptions import ClientError

HEADER_BYTES = 8192

DEFAULT_EXTENSIONS = ".pdf,.docx,.xlsx,.txt,.png,.jpg,.jpeg"

SIGNATURES = {
    ".pdf": [b"%PDF-"],
    ".png": [b"\x89PNG\r\n\x1a\n"],
    ".jpg": [b"\xff\xd8\xff"],
    ".jpeg": [b"\xff\xd8\xff"],
    ".docx": [b"PK\x03\x04"],
    ".xlsx": [b"PK\x03\x04"],
}

CLEAN = "clean"
REJECTED = "rejected"
ERROR = "error"
FINAL_STATES = (CLEAN, REJECTED)
MISSING = ("NoSuchKey", "404")


def _settings():
    extensions = os.environ.get("ALLOWED_EXTENSIONS", DEFAULT_EXTENSIONS)
    return {
        "topic_arn": os.environ.get("SNS_TOPIC_ARN", ""),
        "max_bytes": int(os.environ.get("MAX_FILE_SIZE_MB", "50")) * 1024 * 1024,
        "extensions": {e.strip().lower() for e in extensions.split(",") if e.strip()},
        "tag_objects": os.environ.get("TAG_OBJECTS", "true").lower() == "true",
    }


def _extension(key):
    name = key.rsplit("/", 1)[-1]
    return "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""


def evaluate(key, size, header, settings):
    """Return (status, reason) for an object. Pure function so it can be unit-tested."""
    ext = _extension(key)
    if size == 0:
        return REJECTED, "empty file"
    if size > settings["max_bytes"]:
        return REJECTED, f"larger than {settings['max_bytes'] // (1024 * 1024)} MB"
    if ext not in settings["extensions"]:
        return REJECTED, f"extension '{ext or '(none)'}' is not allowed"
    if ext == ".txt":
        if b"\x00" in header:
            return REJECTED, "binary content in a .txt file"
    elif ext in SIGNATURES and not any(header.startswith(s) for s in SIGNATURES[ext]):
        return REJECTED, f"content does not match the {ext} file signature"
    return CLEAN, "passed size, extension and signature checks"


def _total_size(response, fallback):
    content_range = response.get("ContentRange") or ""
    match = re.search(r"/(\d+)$", content_range)
    return int(match.group(1)) if match else int(response.get("ContentLength", fallback))


def _message(result):
    ok = result["status"] == CLEAN
    lines = [
        "\u2705 FILE SCAN SUCCESSFUL" if ok else "\u274c FILE SCAN FAILED",
        "",
        f"File: {result['key']}",
        f"Bucket: {result['bucket']}",
        f"Size: {result['size']} bytes",
        f"Type: {result['content_type']}",
        f"Scan Result: {'Clean' if ok else 'Rejected - ' + result['reason']}",
        f"Timestamp: {result['timestamp']}",
        "",
        "The file passed the upload checks." if ok
        else "The file failed the upload checks and has been tagged scan-status=rejected.",
    ]
    subject = "Secure File Upload: Scan Complete" if ok else "Secure File Upload: Scan Failed"
    return subject, "\n".join(lines)


def _tag_value(text):
    """S3 tag values only allow letters, digits, spaces and + - = . _ : / @."""
    return re.sub(r"[^A-Za-z0-9 +\-=._:/@]", "", text)[:256]


def _log(level, message, **fields):
    print(json.dumps({"level": level, "message": message, **fields}))


def _code(error):
    return error.response.get("Error", {}).get("Code")


def _tags(s3, bucket, key):
    response = s3.get_object_tagging(Bucket=bucket, Key=key)
    return {t["Key"]: t["Value"] for t in response.get("TagSet", [])}


def _put_tags(s3, bucket, key, status, reason, etag):
    s3.put_object_tagging(
        Bucket=bucket,
        Key=key,
        Tagging={"TagSet": [
            {"Key": "scan-status", "Value": status},
            {"Key": "scan-reason", "Value": _tag_value(reason)},
            {"Key": "scan-etag", "Value": _tag_value(etag)},
        ]},
    )


def scan_record(record, s3, sns, settings, request_id=None):
    bucket = record["s3"]["bucket"]["name"]
    key = unquote_plus(record["s3"]["object"]["key"])
    # The object key is the portal's random storage key, so it correlates these logs with the app's audit trail.
    correlation = {"bucket": bucket, "key": key, "request_id": request_id}

    try:
        obj = s3.get_object(Bucket=bucket, Key=key, Range=f"bytes=0-{HEADER_BYTES - 1}")
    except ClientError as e:
        if _code(e) in MISSING:
            _log("WARNING", "object deleted before it could be scanned", **correlation)
            return None
        if _code(e) == "InvalidRange":
            obj = s3.head_object(Bucket=bucket, Key=key)
            obj["Body"] = None
        else:
            raise

    etag = (obj.get("ETag") or "").strip('"')
    try:
        if settings["tag_objects"]:
            existing = _tags(s3, bucket, key)
            if existing.get("scan-status") in FINAL_STATES and existing.get("scan-etag") == etag:
                _log("INFO", "duplicate event for an already scanned object version; skipped", etag=etag, **correlation)
                return None

        header = obj["Body"].read() if obj.get("Body") else b""
        size = _total_size(obj, record["s3"]["object"].get("size", len(header)))
        status, reason = evaluate(key, size, header, settings)

        result = {
            **correlation,
            "etag": etag,
            "size": size,
            "content_type": obj.get("ContentType", "unknown"),
            "status": status,
            "reason": reason,
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        }

        # Alert first, then record the result: if tagging fails the retry may alert twice (at-least-once),
        # but an alert is never lost because the object was already marked as scanned.
        if settings["topic_arn"]:
            subject, body = _message(result)
            sns.publish(TopicArn=settings["topic_arn"], Subject=subject, Message=body)

        if settings["tag_objects"]:
            _put_tags(s3, bucket, key, status, reason, etag)
    except ClientError as e:
        if _code(e) in MISSING:
            # The portal promotes approved files out of quarantine, which can race with this function.
            _log("INFO", "object removed while scanning (already processed by the portal)", **correlation)
            return None
        _mark_error(s3, bucket, key, etag, settings, correlation)
        raise
    except Exception:
        _mark_error(s3, bucket, key, etag, settings, correlation)
        raise

    _log("INFO", "scan complete", **result)
    return result


def _mark_error(s3, bucket, key, etag, settings, correlation):
    """Best-effort scan-status=error so a failed scan is visible; Lambda's retry will scan again."""
    _log("ERROR", "scan failed; will be retried", **correlation)
    if not settings["tag_objects"]:
        return
    try:
        _put_tags(s3, bucket, key, ERROR, "scan failed, retrying", etag)
    except ClientError:
        pass


def lambda_handler(event, context):
    settings = _settings()
    s3 = boto3.client("s3")
    sns = boto3.client("sns")
    results = [
        scan_record(r, s3, sns, settings, getattr(context, "aws_request_id", None))
        for r in event.get("Records", [])
        if r.get("eventSource") == "aws:s3"
    ]
    return {"scanned": [r for r in results if r]}
