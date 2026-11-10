# FileGuard

Upload a file, get a virus verdict. ClamAV scans it inside Docker. Locally, LocalStack stands in for AWS.

```
Browser -> API (FastAPI) -> presigned upload -> S3 quarantine -> SQS -> Worker + ClamAV
                                  DynamoDB <- verdict ---------------------+
                                  clean -> S3 clean bucket,  infected -> SNS alert
```

## Run it

```
docker compose up --build
```

The first start takes a few minutes because ClamAV downloads its signature database.
The worker waits until ClamAV reports healthy. Watch progress with `docker compose ps`.

Then open http://localhost:8000 and upload a file, or press **Scan the EICAR test virus**.

## Test it

```
python scripts/smoke_test.py
```

Uploads a clean file and the EICAR test file and expects CLEAN and INFECTED.

## Useful commands

```
docker compose logs -f worker     # scanner activity
docker compose logs -f api
docker stats                      # real memory use of the ClamAV container
docker compose down               # stop (keeps the signature database volume)
docker compose down -v            # stop and delete the signature database
```

## Layout

```
api/                FastAPI service and the upload page (api/static)
worker/             SQS consumer that talks to ClamAV
infra/localstack/   init.sh creates the buckets, queues, table and topic
scripts/            smoke_test.py
```

## Notes

- The EICAR test string is never written to disk, because antivirus on your PC would delete the file.
  The UI button and the smoke test both build it in memory.
- Limit is 25 MB. The API enforces it, S3 enforces it through the presigned form, and the worker checks it again.
- If a scan crashes, SQS retries it up to 3 times, then moves it to the dead-letter queue and the record shows ERROR.
