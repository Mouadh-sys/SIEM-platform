#!/usr/bin/env bash
# scripts/create_index_template.sh
# Creates the OpenSearch index template and index for security-logs.
# Run before Data Prepper can consume events so dynamic mappings never win.
# Run: bash scripts/create_index_template.sh
set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:-http://localhost:9200}"
TEMPLATE_NAME="security-logs-template"
INDEX_NAME="security-logs"
RECREATE="${RECREATE_MISMATCHED_INDEX:-false}"

echo "[*] Waiting for OpenSearch to be ready..."
until curl -sf "${OPENSEARCH_URL}/_cluster/health" | grep -qE '"status":"(green|yellow)"'; do
  echo "    ... not yet ready, retrying in 3s"
  sleep 3
done
echo "[✓] OpenSearch is up."

echo "[*] Creating index template '${TEMPLATE_NAME}'..."
curl -sf -o /dev/null -X PUT "${OPENSEARCH_URL}/_index_template/${TEMPLATE_NAME}" \
  -H "Content-Type: application/json" \
  -d '{
  "index_patterns": ["security-logs*"],
  "priority": 100,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0
    },
    "mappings": {
      "properties": {
        "@timestamp":    { "type": "date" },
        "timestamp":     { "type": "keyword" },
        "src_ip":        { "type": "ip" },
        "user":          { "type": "keyword" },
        "event_action":  { "type": "keyword" },
        "host":          { "type": "keyword" },
        "process":       { "type": "keyword" },
        "pid":           { "type": "keyword" },
        "port":          { "type": "integer" },
        "parse_failed":  { "type": "boolean" },
        "message":       { "type": "text", "fields": { "keyword": { "type": "keyword", "ignore_above": 512 } } },
        "doc_id":        { "type": "keyword" },
        "log_type":      { "type": "keyword" }
      }
    }
  }
}'
echo "[✓] Index template '${TEMPLATE_NAME}' created."

echo "[*] Checking index '${INDEX_NAME}'..."
INDEX_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "${OPENSEARCH_URL}/${INDEX_NAME}")
RECREATE_INDEX=false

if [[ "${INDEX_STATUS}" == "200" ]]; then
  MAPPING=$(curl -sf "${OPENSEARCH_URL}/${INDEX_NAME}/_mapping" | tr -d '[:space:]')
  SETTINGS=$(curl -sf "${OPENSEARCH_URL}/${INDEX_NAME}/_settings" | tr -d '[:space:]')

  if ! grep -q '"src_ip":{"type":"ip"' <<<"${MAPPING}"; then
    echo "[!] Existing index does not map src_ip as an ip field."
    RECREATE_INDEX=true
  fi

  if ! grep -q '"number_of_replicas":"0"' <<<"${SETTINGS}"; then
    echo "[!] Existing index does not use 0 replicas."
    RECREATE_INDEX=true
  fi

  if [[ "${RECREATE_INDEX}" == "true" ]]; then
    if [[ "${RECREATE}" != "true" ]]; then
      echo "ERROR: index '${INDEX_NAME}' has an incompatible mapping or settings." >&2
      echo "       Delete it, or rerun with RECREATE_MISMATCHED_INDEX=true." >&2
      exit 1
    fi
    echo "[!] Recreating index '${INDEX_NAME}'..."
    curl -sf -o /dev/null -X DELETE "${OPENSEARCH_URL}/${INDEX_NAME}"
  else
    echo "[✓] Existing index has a compatible mapping and settings."
  fi
fi

if [[ "${INDEX_STATUS}" != "200" || "${RECREATE_INDEX}" == "true" ]]; then
  echo "[*] Creating index '${INDEX_NAME}' from the template..."
  curl -sf -o /dev/null -X PUT "${OPENSEARCH_URL}/${INDEX_NAME}" \
    -H "Content-Type: application/json" \
    -d '{"settings":{"number_of_shards":1,"number_of_replicas":0}}'
fi

MAPPING=$(curl -sf "${OPENSEARCH_URL}/${INDEX_NAME}/_mapping" | tr -d '[:space:]')
if ! grep -q '"src_ip":{"type":"ip"' <<<"${MAPPING}"; then
  echo "ERROR: index '${INDEX_NAME}' was not created with the expected mapping." >&2
  exit 1
fi

echo "[✓] Index '${INDEX_NAME}' is ready with the correct mapping."
