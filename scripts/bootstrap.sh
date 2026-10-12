#!/usr/bin/env bash
set -euo pipefail

# bootstrap.sh – bring up the SIEM stack from a clean state
# Usage: ./scripts/bootstrap.sh [--seed]

SEED=false
if [[ "${1:-}" == "--seed" ]]; then
  SEED=true
fi

COMPOSE_FILE="docker-compose.yml"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_DIR}"

echo "=== Starting SIEM stack ==="
docker compose -f "${COMPOSE_FILE}" up -d

# Wait for services health
wait_for_health() {
  local container=$1
  local timeout=${2:-180}
  local interval=5
  local elapsed=0
  echo "Waiting for ${container} to become healthy (timeout ${timeout}s)..."
  while [[ $elapsed -lt $timeout ]]; do
    status=$(docker inspect --format='{{.State.Health.Status}}' "${container}" 2>/dev/null || echo "none")
    if [[ "$status" == "healthy" ]]; then
      echo "${container} is healthy."
      return 0
    fi
    sleep $interval
    elapsed=$((elapsed + interval))
  done
  echo "ERROR: ${container} did not become healthy within ${timeout}s" >&2
  docker logs "${container}" --tail 50
  exit 1
}

wait_for_health siem-opensearch 180
wait_for_health siem-kafka 120
wait_for_health siem-data-prepper 180
wait_for_health siem-portal-backend 120

# Create index template (idempotent)
echo "=== Creating index template ==="
./scripts/create_index_template.sh

# Setup detector (idempotent)
echo "=== Setting up detector (channel + monitor) ==="
python3 scripts/setup_detector.py

# Optional seed
if [[ "$SEED" == true ]]; then
  echo "=== Seeding historical incidents (inside portal-backend) ==="
  docker exec -i siem-portal-backend python3 - <<'PY'
import os, sys, sqlite3, datetime, random
DB_PATH="/app/data/incidents.db"
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
conn=sqlite3.connect(DB_PATH)
cur=conn.cursor()
cur.execute("DELETE FROM incidents")
ATTACKER_IPS=["203.0.113.42","198.51.100.77","192.0.2.14","203.0.113.89","198.51.100.23","203.0.113.156","192.0.2.67","198.51.100.201"]
STATUSES=["open","investigating","resolved","blocked"]
SEVERITIES=[1,2,3,4]
now=datetime.datetime.now(datetime.timezone.utc)
for i in range(30):
    ip=random.choice(ATTACKER_IPS)
    severity=random.choice(SEVERITIES)
    status=random.choice(STATUSES)
    count=random.randint(5,200)
    days_ago=random.randint(0,7)
    hours_ago=random.randint(0,23)
    minutes_ago=random.randint(0,59)
    first_seen=now - datetime.timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
    last_seen=first_seen + datetime.timedelta(minutes=random.randint(5,120))
    notes=[None,"Investigating source network","Confirmed brute-force attack, blocking at firewall","False positive - authorized scanner","Escalated to SOC team","Auto-resolved after IP block"]
    cur.execute("INSERT INTO incidents (src_ip, severity, count, first_seen, last_seen, raw_payload, status, analyst_note) VALUES (?,?,?,?,?,?,?,?)", (ip, severity, count, first_seen.isoformat(), last_seen.isoformat(), f'{{"monitor_name": "ssh-bruteforce-by-ip", "trigger_name": "brute-force-threshold", "severity": "{severity}", "src_ip": "{ip}", "count": "{count}", "period_end": "{last_seen.isoformat()}"}}', status, random.choice(notes))
conn.commit()
conn.close()
print("Seeded 30 historical incidents")
PY
fi

# Print URLs
echo ""
echo "=== SIEM stack ready ==="
echo "OpenSearch:          http://localhost:9200"
echo "OpenSearch Dashboards: http://localhost:5601"
echo "Portal Backend API:  http://localhost:8000"
echo "Portal Frontend:     http://localhost:5173"
echo ""