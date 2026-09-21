#!/usr/bin/env bash
set -euo pipefail

ALLOY_HOST="${ALLOY_HOST:-127.0.0.1}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SNAPPY_PAYLOAD="${SCRIPT_DIR}/sample_write.snappy"

echo "==> 1. Checking Alloy HTTP server on :12345..."
if ! curl -s -f "http://${ALLOY_HOST}:12345/" > /dev/null; then
  echo "    ERROR: Could not connect to Alloy UI / health server at http://${ALLOY_HOST}:12345/"
  echo "    Is Alloy running? (Run 'devenv up' or 'run-alloy' first)"
  exit 1
fi
echo "    Alloy HTTP server is healthy."

echo "==> 2. Testing OTLP HTTP receiver on :4318/v1/metrics (JSON payload)..."
OTLP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://${ALLOY_HOST}:4318/v1/metrics" \
  -H "Content-Type: application/json" \
  -d '{
    "resourceMetrics": [{
      "resource": {
        "attributes": [{ "key": "service.name", "value": { "stringValue": "standalone-test" } }]
      },
      "scopeMetrics": [{
        "metrics": [{
          "name": "standalone_test_gauge",
          "gauge": {
            "dataPoints": [{ "asDouble": 42.0 }]
          }
        }]
      }]
    }]
  }')

if [ "$OTLP_STATUS" != "200" ]; then
  echo "    ERROR: OTLP endpoint returned HTTP $OTLP_STATUS (expected 200)"
  exit 1
fi
echo "    OTLP HTTP receiver accepted metric (HTTP $OTLP_STATUS)."

echo "==> 3. Testing Prometheus remote_write receiver on :9999/api/v1/metrics/write..."
if [ ! -f "$SNAPPY_PAYLOAD" ]; then
  echo "    ERROR: Sample snappy payload not found at $SNAPPY_PAYLOAD"
  exit 1
fi

PROM_STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://${ALLOY_HOST}:9999/api/v1/metrics/write" \
  -H "Content-Type: application/x-protobuf" \
  -H "Content-Encoding: snappy" \
  --data-binary "@${SNAPPY_PAYLOAD}")

if [ "$PROM_STATUS" != "204" ] && [ "$PROM_STATUS" != "200" ]; then
  echo "    ERROR: Prometheus remote_write endpoint returned HTTP $PROM_STATUS (expected 204 or 200)"
  exit 1
fi
echo "    Prometheus remote_write receiver accepted metric (HTTP $PROM_STATUS)."

echo "==> All receivers tested successfully and independently!"
