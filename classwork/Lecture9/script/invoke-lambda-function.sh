#!/usr/bin/env bash
if [ -z "$2" ]; then
    echo "Usage: ./scripts/invoke-lambda-function.sh <BUCKET_NAME> <IMAGE_KEY>"
    exit 1
fi

BUCKET_NAME="$1"
IMAGE_KEY="$2"
LAMBDA_FUNCTION_NAME="cfn-python-function"

PAYLOAD="{\"Records\":[{\"s3\":{\"bucket\":{\"name\":\"$BUCKET_NAME\"},\"object\":{\"key\":\"$IMAGE_KEY\"}}}]}"

aws lambda invoke \
  --function-name "${LAMBDA_FUNCTION_NAME}" \
  --cli-binary-format raw-in-base64-out \
  --payload "$PAYLOAD" \
  response.json

cat response.json
