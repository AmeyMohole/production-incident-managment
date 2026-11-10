"""FileGuard API.

Creates a scan record, hands the browser a presigned S3 upload form, and reports
scan results. It never touches the file itself: the worker does the scanning.
"""
import logging
import os
import time
import uuid
from decimal import Decimal

import boto3
from botocore.config import Config
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("fileguard.api")

QUARANTINE_BUCKET = os.environ["QUARANTINE_BUCKET"]
SCANS_TABLE = os.environ["SCANS_TABLE"]
MAX_FILE_BYTES = int(os.environ.get("MAX_FILE_MB", "25")) * 1024 * 1024
UPLOAD_URL_TTL = 300  # seconds
RECORD_TTL = 7 * 24 * 3600  # DynamoDB TTL, seconds

# Inside Docker the API reaches LocalStack by service name, but the browser must
# use localhost. In real AWS both endpoints are unset and the defaults apply.
INTERNAL_ENDPOINT = os.environ.get("AWS_ENDPOINT_URL") or None
PUBLIC_ENDPOINT = os.environ.get("PUBLIC_S3_ENDPOINT") or INTERNAL_ENDPOINT

dynamodb = boto3.resource("dynamodb", endpoint_url=INTERNAL_ENDPOINT)
table = dynamodb.Table(SCANS_TABLE)
s3_public = boto3.client(
    "s3",
    endpoint_url=PUBLIC_ENDPOINT,
    config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
)

app = FastAPI(title="FileGuard", version="1.0.0")


class UploadRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    size: int = Field(gt=0)
    content_type: str = Field(default="application/octet-stream", max_length=200)


def clean(value):
    """DynamoDB returns Decimal, which JSON cannot encode."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/uploads", status_code=201)
def create_upload(req: UploadRequest):
    if req.size > MAX_FILE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File is too large. The limit is {MAX_FILE_BYTES // (1024 * 1024)} MB.",
        )

    scan_id = uuid.uuid4().hex
    now = int(time.time())
    key = f"uploads/{scan_id}"

    table.put_item(
        Item={
            "scan_id": scan_id,
            "filename": req.filename,
            "size": req.size,
            "content_type": req.content_type,
            "status": "PENDING",
            "created_at": now,
            "updated_at": now,
            "expires_at": now + RECORD_TTL,
        }
    )

    # A presigned POST lets S3 itself enforce the size limit.
    upload = s3_public.generate_presigned_post(
        Bucket=QUARANTINE_BUCKET,
        Key=key,
        Conditions=[["content-length-range", 1, MAX_FILE_BYTES]],
        ExpiresIn=UPLOAD_URL_TTL,
    )
    log.info("upload created scan_id=%s filename=%r size=%d", scan_id, req.filename, req.size)
    return {"scan_id": scan_id, "upload": upload}


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    item = table.get_item(Key={"scan_id": scan_id}).get("Item")
    if not item:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return clean(item)


@app.get("/scans")
def list_scans(limit: int = 20):
    # A table scan is fine at demo scale. Add an index if this grows.
    items = table.scan().get("Items", [])
    items.sort(key=lambda i: i.get("created_at", 0), reverse=True)
    return clean(items[: max(1, min(limit, 100))])


# The upload page. Mounted last so the API routes above take priority.
app.mount("/", StaticFiles(directory="static", html=True), name="static")
