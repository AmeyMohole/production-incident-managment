"""End-to-end check: upload a clean file and the EICAR test file, expect CLEAN and INFECTED.

Run from the project root after `docker compose up`:
    python scripts/smoke_test.py

The EICAR string is built from pieces and sent from memory, so no file containing it
is ever written to disk (Windows Defender would quarantine one).
"""
import json
import sys
import time
import urllib.error
import urllib.request
import uuid

API = "http://localhost:8000"
EICAR = "".join(["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!", "$H+H*"]).encode()


def api(method, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(API + path, data=data, method=method, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def post_to_s3(upload, content):
    """Send a multipart/form-data POST using the presigned fields. The file part must be last."""
    boundary = uuid.uuid4().hex
    body = b""
    for name, value in upload["fields"].items():
        body += f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode()
    body += f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="upload"\r\n\r\n'.encode()
    body += content + f"\r\n--{boundary}--\r\n".encode()
    req = urllib.request.Request(
        upload["url"], data=body, method="POST",
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    )
    urllib.request.urlopen(req, timeout=30).read()


def scan(filename, content, timeout=300):
    created = api("POST", "/uploads", {"filename": filename, "size": len(content)})
    post_to_s3(created["upload"], content)
    deadline = time.time() + timeout
    while time.time() < deadline:
        record = api("GET", "/scans/" + created["scan_id"])
        if record["status"] in ("CLEAN", "INFECTED", "ERROR"):
            return record
        time.sleep(2)
    raise SystemExit(f"Timed out waiting for {filename}. Is the worker running?")


def main():
    failures = 0
    cases = [
        ("hello.txt", b"Just a harmless text file.\n", "CLEAN"),
        ("eicar-test.txt", EICAR, "INFECTED"),
    ]
    for name, content, expected in cases:
        record = scan(name, content)
        ok = record["status"] == expected
        failures += not ok
        extra = f" ({record.get('signature')})" if record.get("signature") else ""
        print(f"{'PASS' if ok else 'FAIL'}  {name}: expected {expected}, got {record['status']}{extra}")
        if record["status"] == "ERROR":
            print("      error:", record.get("error"))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
