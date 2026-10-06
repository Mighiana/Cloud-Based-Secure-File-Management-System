import json

import boto3
import pytest
from moto import mock_aws

import handler

BUCKET = "secure-files"
PDF = b"%PDF-1.7\n" + b"x" * 100
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 50
ZIP = b"PK\x03\x04" + b"\x00" * 50
EXE = b"MZ\x90\x00" + b"\x00" * 50


def settings(**overrides):
    base = {
        "topic_arn": "",
        "max_bytes": 50 * 1024 * 1024,
        "extensions": {".pdf", ".docx", ".xlsx", ".txt", ".png", ".jpg", ".jpeg"},
        "tag_objects": True,
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize("key,header", [
    ("a.pdf", PDF), ("a.png", PNG), ("a.docx", ZIP), ("a.xlsx", ZIP),
    ("a.jpg", b"\xff\xd8\xff\xe0rest"), ("A.JPEG", b"\xff\xd8\xff\xe1rest"),
    ("notes.txt", "héllo wörld".encode()),
])
def test_valid_files_are_clean(key, header):
    assert handler.evaluate(key, len(header), header, settings())[0] == handler.CLEAN


@pytest.mark.parametrize("key,size,header,reason", [
    ("a.pdf", 0, b"", "empty"),
    ("a.pdf", 51 * 1024 * 1024, PDF, "larger than 50 MB"),
    ("a.exe", 60, EXE, "not allowed"),
    ("noextension", 60, PDF, "(none)"),
    ("a.pdf", 60, EXE, "signature"),
    ("a.png", 60, PDF, "signature"),
    ("a.docx", 60, PDF, "signature"),
    ("a.txt", 60, b"abc\x00def", "binary"),
])
def test_invalid_files_are_rejected(key, size, header, reason):
    status, why = handler.evaluate(key, size, header, settings())
    assert status == handler.REJECTED
    assert reason in why


def test_tag_values_only_use_characters_s3_accepts():
    assert handler._tag_value("extension '.exe' is not allowed, sorry!") == "extension .exe is not allowed sorry"


def test_settings_parse_environment(monkeypatch):
    monkeypatch.setenv("ALLOWED_EXTENSIONS", " .PDF, .txt ,,")
    monkeypatch.setenv("MAX_FILE_SIZE_MB", "5")
    monkeypatch.setenv("TAG_OBJECTS", "false")
    s = handler._settings()
    assert s["extensions"] == {".pdf", ".txt"}
    assert s["max_bytes"] == 5 * 1024 * 1024
    assert s["tag_objects"] is False


def s3_event(key, size):
    return {"Records": [{
        "eventSource": "aws:s3",
        "s3": {"bucket": {"name": BUCKET}, "object": {"key": key, "size": size}},
    }]}


@pytest.fixture
def aws(monkeypatch):
    with mock_aws():
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket=BUCKET,
                         CreateBucketConfiguration={"LocationConstraint": "eu-north-1"})
        sns = boto3.client("sns")
        topic = sns.create_topic(Name="FileUploadAlerts")["TopicArn"]
        sqs = boto3.client("sqs")
        queue = sqs.create_queue(QueueName="alerts")["QueueUrl"]
        queue_arn = sqs.get_queue_attributes(
            QueueUrl=queue, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
        sns.subscribe(TopicArn=topic, Protocol="sqs", Endpoint=queue_arn)
        monkeypatch.setenv("SNS_TOPIC_ARN", topic)

        def alerts():
            msgs = sqs.receive_message(QueueUrl=queue, MaxNumberOfMessages=10).get("Messages", [])
            return [json.loads(m["Body"]) for m in msgs]

        yield s3, alerts


def tags(s3, key):
    return {t["Key"]: t["Value"] for t in s3.get_object_tagging(Bucket=BUCKET, Key=key)["TagSet"]}


def test_clean_upload_is_tagged_and_alerted(aws):
    s3, alerts = aws
    s3.put_object(Bucket=BUCKET, Key="report.pdf", Body=PDF, ContentType="application/pdf")

    out = handler.lambda_handler(s3_event("report.pdf", len(PDF)), None)

    assert out["scanned"][0]["status"] == "clean"
    assert out["scanned"][0]["size"] == len(PDF)
    assert tags(s3, "report.pdf")["scan-status"] == "clean"
    [alert] = alerts()
    assert alert["Subject"] == "Secure File Upload: Scan Complete"
    assert "FILE SCAN SUCCESSFUL" in alert["Message"]
    assert "Bucket: secure-files" in alert["Message"]
    assert "Type: application/pdf" in alert["Message"]
    assert "Scan Result: Clean" in alert["Message"]


def test_disguised_executable_is_rejected(aws):
    s3, alerts = aws
    s3.put_object(Bucket=BUCKET, Key="invoice.pdf", Body=EXE)

    out = handler.lambda_handler(s3_event("invoice.pdf", len(EXE)), None)

    assert out["scanned"][0]["status"] == "rejected"
    t = tags(s3, "invoice.pdf")
    assert t["scan-status"] == "rejected"
    assert t["scan-reason"] == "content does not match the .pdf file signature"
    assert t["scan-etag"] == out["scanned"][0]["etag"]
    [alert] = alerts()
    assert alert["Subject"] == "Secure File Upload: Scan Failed"
    assert "FILE SCAN FAILED" in alert["Message"]
    assert "signature" in alert["Message"]


def test_size_comes_from_s3_not_the_header_range(aws, monkeypatch):
    s3, _ = aws
    monkeypatch.setenv("MAX_FILE_SIZE_MB", "1")
    body = PDF + b"x" * (1024 * 1024)
    s3.put_object(Bucket=BUCKET, Key="big.pdf", Body=body)

    out = handler.lambda_handler(s3_event("big.pdf", 1), None)

    assert out["scanned"][0]["size"] == len(body)
    assert out["scanned"][0]["status"] == "rejected"


def test_empty_object_is_rejected(aws):
    s3, _ = aws
    s3.put_object(Bucket=BUCKET, Key="empty.txt", Body=b"")

    out = handler.lambda_handler(s3_event("empty.txt", 0), None)

    assert out["scanned"][0]["reason"] == "empty file"


def test_url_encoded_keys_are_decoded(aws):
    s3, _ = aws
    s3.put_object(Bucket=BUCKET, Key="my notes.txt", Body=b"hello")

    out = handler.lambda_handler(s3_event("my+notes.txt", 5), None)

    assert out["scanned"][0]["key"] == "my notes.txt"
    assert tags(s3, "my notes.txt")["scan-status"] == "clean"


def test_deleted_object_is_skipped(aws):
    _, alerts = aws
    out = handler.lambda_handler(s3_event("gone.pdf", 10), None)
    assert out == {"scanned": []}
    assert alerts() == []


def test_tagging_and_alerts_can_be_disabled(aws, monkeypatch):
    s3, alerts = aws
    monkeypatch.setenv("TAG_OBJECTS", "false")
    monkeypatch.setenv("SNS_TOPIC_ARN", "")
    s3.put_object(Bucket=BUCKET, Key="a.pdf", Body=PDF)

    handler.lambda_handler(s3_event("a.pdf", len(PDF)), None)

    assert tags(s3, "a.pdf") == {}
    assert alerts() == []


def test_non_s3_records_are_ignored(aws):
    assert handler.lambda_handler({"Records": [{"eventSource": "aws:sqs"}]}, None) == {"scanned": []}


def test_duplicate_event_is_skipped_without_a_second_alert(aws):
    s3, alerts = aws
    s3.put_object(Bucket=BUCKET, Key="dup.pdf", Body=PDF)
    event = s3_event("dup.pdf", len(PDF))

    first = handler.lambda_handler(event, None)
    second = handler.lambda_handler(event, None)

    assert len(first["scanned"]) == 1
    assert second == {"scanned": []}
    assert len(alerts()) == 1


def test_new_object_version_is_scanned_again(aws):
    s3, alerts = aws
    s3.put_object(Bucket=BUCKET, Key="v.pdf", Body=PDF)
    handler.lambda_handler(s3_event("v.pdf", len(PDF)), None)
    s3.put_object(Bucket=BUCKET, Key="v.pdf", Body=EXE)

    out = handler.lambda_handler(s3_event("v.pdf", len(EXE)), None)

    assert out["scanned"][0]["status"] == "rejected"
    assert len(alerts()) == 2


def test_failure_marks_error_and_reraises_for_retry(aws, monkeypatch):
    s3, alerts = aws
    s3.put_object(Bucket=BUCKET, Key="boom.pdf", Body=PDF)

    def fail(*_, **__):
        raise RuntimeError("sns down")

    monkeypatch.setattr(handler, "_message", fail)
    with pytest.raises(RuntimeError):
        handler.lambda_handler(s3_event("boom.pdf", len(PDF)), None)
    assert tags(s3, "boom.pdf")["scan-status"] == "error"

    # A retry after an error is not treated as a duplicate.
    monkeypatch.undo()
    monkeypatch.setenv("SNS_TOPIC_ARN", "")
    out = handler.lambda_handler(s3_event("boom.pdf", len(PDF)), None)
    assert out["scanned"][0]["status"] == "clean"


def test_request_id_is_logged_for_correlation(aws, capsys):
    s3, _ = aws
    s3.put_object(Bucket=BUCKET, Key="c.txt", Body=b"hi")

    class Ctx:
        aws_request_id = "req-123"

    handler.lambda_handler(s3_event("c.txt", 2), Ctx())
    line = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    assert line["request_id"] == "req-123"
    assert line["key"] == "c.txt"
