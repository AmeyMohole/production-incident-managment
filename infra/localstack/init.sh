#!/bin/sh
# Creates the same resources the Terraform setup will create in real AWS.
# Safe to run repeatedly.
set -e

AWS="aws --endpoint-url http://localstack:4566"
QUARANTINE=fileguard-quarantine
CLEAN=fileguard-clean

echo "Creating buckets..."
$AWS s3api create-bucket --bucket $QUARANTINE >/dev/null 2>&1 || true
$AWS s3api create-bucket --bucket $CLEAN >/dev/null 2>&1 || true

# Browser uploads go straight to S3, so the bucket must allow cross-origin POST.
$AWS s3api put-bucket-cors --bucket $QUARANTINE --cors-configuration '{
  "CORSRules": [{
    "AllowedOrigins": ["*"],
    "AllowedMethods": ["POST", "PUT"],
    "AllowedHeaders": ["*"],
    "MaxAgeSeconds": 300
  }]
}'

echo "Creating queues..."
$AWS sqs create-queue --queue-name fileguard-scan-dlq >/dev/null
DLQ_URL=$($AWS sqs get-queue-url --queue-name fileguard-scan-dlq --query QueueUrl --output text)
DLQ_ARN=$($AWS sqs get-queue-attributes --queue-url "$DLQ_URL" --attribute-names QueueArn --query Attributes.QueueArn --output text)

# After 3 failed receives a message moves to the dead-letter queue.
$AWS sqs create-queue --queue-name fileguard-scan-queue --attributes "{
  \"VisibilityTimeout\": \"120\",
  \"RedrivePolicy\": \"{\\\"deadLetterTargetArn\\\":\\\"$DLQ_ARN\\\",\\\"maxReceiveCount\\\":\\\"3\\\"}\"
}" >/dev/null
Q_URL=$($AWS sqs get-queue-url --queue-name fileguard-scan-queue --query QueueUrl --output text)
Q_ARN=$($AWS sqs get-queue-attributes --queue-url "$Q_URL" --attribute-names QueueArn --query Attributes.QueueArn --output text)

echo "Wiring S3 uploads to the queue..."
$AWS s3api put-bucket-notification-configuration --bucket $QUARANTINE --notification-configuration "{
  \"QueueConfigurations\": [{
    \"QueueArn\": \"$Q_ARN\",
    \"Events\": [\"s3:ObjectCreated:*\"]
  }]
}"

echo "Creating table and topic..."
$AWS dynamodb create-table \
  --table-name fileguard-scans \
  --attribute-definitions AttributeName=scan_id,AttributeType=S \
  --key-schema AttributeName=scan_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST >/dev/null 2>&1 || true

$AWS sns create-topic --name fileguard-alerts >/dev/null

echo "FileGuard resources ready."
