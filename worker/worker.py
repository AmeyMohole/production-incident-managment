"""FileGuard scanner worker.

Long-polls SQS for S3 upload events, streams each file to ClamAV, records the
verdict in DynamoDB, moves clean files to the clean bucket, and raises an SNS
alert for infected ones. The file is only ever read as bytes, never executed.
"""
import hashlib
import json
import logging
import os
import signal
import time
import urllib.parse

import boto3
import clamd

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fileguard.worker")

ENDPOINT = os.environ.get("AWS_ENDPOINT_URL") or None
QUARANTINE_BUCKET = os.environ["QUARANTINE_BUCKET"]
CLEAN_BUCKET = os.environ["CLEAN_BUCKET"]
SCANS_TABLE = os.environ["SCANS_TABLE"]
SCAN_QUEUE = os.environ["SCAN_QUEUE"]
ALERT_TOPIC = os.environ["ALERT_TOPIC"]
CLAMD_HOST = os.environ.get("CLAMD_HOST", "localhost")
CLAMD_PORT = int(os.environ.get("CLAMD_PORT", "3310"))
MAX_FILE_BYTES = int(os.environ.get("MAX_FILE_MB", "25")) * 1024 * 1024
MAX_RECEIVES = int(os.environ.get("MAX_RECEIVES", "3"))

s3 = boto3.client("s3", endpoint_url=ENDPOINT)
sqs = boto3.client("sqs", endpoint_url=ENDPOINT)
sns = boto3.client("sns", endpoint_url=ENDPOINT)
table = boto3.resource("dynamodb", endpoint_url=ENDPOINT).Table(SCANS_TABLE)

running = True
topic_arn = None


def stop(*_):
    global running
    running = False
    log.info("shutdown requested, finishing current message")


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)


class HashingReader:
    """Wraps a stream so the SHA-256 is computed while ClamAV reads it."""

    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        chunk = self.stream.read(size)
        self.digest.update(chunk)
        return chunk


def connect_clamd():
    """Wait until ClamAV answers. It takes a while to load signatures at start."""
    while running:
        try:
            cd = clamd.ClamdNetworkSocket(host=CLAMD_HOST, port=CLAMD_PORT, timeout=60)
            cd.ping()
            log.info("connected to clamd %s:%s, version %s", CLAMD_HOST, CLAMD_PORT, cd.version())
            return cd
        except Exception as exc:  # noqa: BLE001
            log.warning("clamd not ready (%s), retrying in 5s", exc)
            time.sleep(5)
    raise SystemExit(0)


def set_status(scan_id, status, **extra):
    now = int(time.time())
    fields = {"status": status, "updated_at": now, **extra}
    names = {f"#{k}": k for k in fields}
    values = {f":{k}": v for k, v in fields.items()}
    expr = "SET " + ", ".join(f"#{k} = :{k}" for k in fields)
    table.update_item(
        Key={"scan_id": scan_id},
        UpdateExpression=expr,
        ExpressionAttributeNames=names,
        ExpressionAttributeValues=values,
    )


def scan_object(cd, key, scan_id):
    """Stream one quarantined object through ClamAV and act on the verdict."""
    head = s3.head_object(Bucket=QUARANTINE_BUCKET, Key=key)
    size = head["ContentLength"]
    if size > MAX_FILE_BYTES:
        set_status(scan_id, "ERROR", error=f"File is {size} bytes, over the limit.")
        log.warning("scan_id=%s too large (%d bytes)", scan_id, size)
        return

    set_status(scan_id, "SCANNING")
    started = time.time()
    body = s3.get_object(Bucket=QUARANTINE_BUCKET, Key=key)["Body"]
    reader = HashingReader(body)
    result = cd.instream(reader)["stream"]
    verdict, signature = result[0], result[1]
    sha256 = reader.digest.hexdigest()
    seconds = round(time.time() - started, 2)

    if verdict == "OK":
        s3.copy_object(
            Bucket=CLEAN_BUCKET,
            Key=key,
            CopySource={"Bucket": QUARANTINE_BUCKET, "Key": key},
        )
        s3.delete_object(Bucket=QUARANTINE_BUCKET, Key=key)
        set_status(scan_id, "CLEAN", sha256=sha256, scan_seconds=str(seconds))
        log.info("scan_id=%s CLEAN sha256=%s in %ss", scan_id, sha256, seconds)
    elif verdict == "FOUND":
        set_status(scan_id, "INFECTED", signature=signature, sha256=sha256, scan_seconds=str(seconds))
        log.warning("scan_id=%s INFECTED signature=%s sha256=%s", scan_id, signature, sha256)
        sns.publish(
            TopicArn=topic_arn,
            Subject="FileGuard: infected file detected",
            Message=json.dumps({"scan_id": scan_id, "signature": signature, "sha256": sha256}),
        )
    else:
        # ClamAV said it could not scan the file. Never treat that as clean.
        set_status(scan_id, "ERROR", error=f"ClamAV: {signature or verdict}")
        log.error("scan_id=%s ERROR from clamd: %s %s", scan_id, verdict, signature)


def handle_message(cd, message):
    """Returns True when the message is finished and should be deleted."""
    body = json.loads(message["Body"])
    if body.get("Event") == "s3:TestEvent":
        return True

    receives = int(message["Attributes"].get("ApproximateReceiveCount", "1"))
    for record in body.get("Records", []):
        key = urllib.parse.unquote_plus(record["s3"]["object"]["key"])
        scan_id = key.split("/")[-1]
        try:
            scan_object(cd, key, scan_id)
        except Exception as exc:  # noqa: BLE001
            log.exception("scan_id=%s failed (attempt %d/%d)", scan_id, receives, MAX_RECEIVES)
            if receives >= MAX_RECEIVES:
                # Last attempt: SQS moves the message to the dead-letter queue next.
                set_status(scan_id, "ERROR", error=f"Scan failed after {receives} attempts: {exc}")
            return False  # keep the message so SQS redelivers it, or dead-letters it
    return True


def main():
    global topic_arn
    queue_url = sqs.get_queue_url(QueueName=SCAN_QUEUE)["QueueUrl"]
    topic_arn = sns.create_topic(Name=ALERT_TOPIC)["TopicArn"]
    cd = connect_clamd()
    log.info("worker ready, polling %s", queue_url)

    while running:
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=10,
            AttributeNames=["ApproximateReceiveCount"],
        )
        for message in resp.get("Messages", []):
            if handle_message(cd, message):
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=message["ReceiptHandle"])


if __name__ == "__main__":
    main()
