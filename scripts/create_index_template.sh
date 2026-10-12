#!/usr/bin/env bash
# scripts/create_index_template.sh
# Creates the OpenSearch index template for security-logs BEFORE Data Prepper starts.
# Run: bash scripts/create_index_template.sh
set -euo pipefail

OPENSEARCH_URL="${OPENSEARCH_URL:-http://localhost:9200}"
TEMPLATE_NAME="security-logs-template"

echo "[*] Waiting for OpenSearch to be ready..."
until curl -sf "${OPENSEARCH_URL}/_cluster/health" | grep -qE '"status":"(green|yellow)"'; do
  echo "    ... not yet ready, retrying in 3s"
  sleep 3
done
echo "[✓] OpenSearch is up."

echo "[*] Creating index template '${TEMPLATE_NAME}'..."
curl -sf -X PUT "${OPENSEARCH_URL}/_index_template/${TEMPLATE_NAME}" \
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
echo ""
echo "[✓] Index template '${TEMPLATE_NAME}' created."

# Pre-create the index so settings apply immediately
echo "[*] Ensuring index 'security-logs' exists..."
curl -sf -o /dev/null -X PUT "${OPENSEARCH_URL}/security-logs" \
  -H "Content-Type: application/json" \
  -d '{"settings":{"number_of_shards":1,"number_of_replicas":0}}' || true
echo "[✓] Index 'security-logs' ready."
