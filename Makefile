.PHONY: up demo demo-compromise demo-spray reset logs seed

COMPOSE=docker compose -f docker-compose.yml

up:
	@echo "=== Bringing up stack ==="
	$(COMPOSE) up -d
	@./scripts/bootstrap.sh

seed:
	@echo "=== Seeding incidents ==="
	@./scripts/bootstrap.sh --seed

demo:
	@echo "=== Running brute-force demo from two attacker IPs ==="
	# first attacker
	python3 scripts/replay_auth_log.py -c 12 -m brute-force -a 203.0.113.42
	# second attacker
	python3 scripts/replay_auth_log.py -c 12 -m brute-force -a 198.51.100.77
	@echo "Waiting for monitor to fire (up to 90s)..."
	@timeout 90 bash -c 'while true; do \
	  alert=$$(curl -s "http://localhost:9200/_plugins/_alerting/monitors/alerts?size=1" | jq -r ".alerts[0].state // \"none\""); \
	  if [[ "$$alert" == "ACTIVE" ]]; then echo "Monitor ACTIVE"; break; fi; \
	  sleep 3; done' || true
	@echo "=== Current incidents ==="
	@curl -s http://localhost:8000/incidents | jq .

demo-compromise:
	@echo "=== Running compromise demo (failed then success) ==="
	python3 scripts/replay_auth_log.py -c 8 -m compromise -a 203.0.113.42
	@echo "Waiting for compromise monitor (up to 120s)..."
	@timeout 120 bash -c 'while true; do \
	  alert=$$(curl -s "http://localhost:9200/_plugins/_alerting/monitors/alerts?size=5" | jq -r ".alerts[] | select(.monitor_name==\"ssh-bruteforce-then-success\") | .state // \"none\""); \
	  if [[ "$$alert" == "ACTIVE" ]]; then echo "Compromise monitor ACTIVE"; break; fi; \
	  sleep 3; done' || true
	@echo "=== Incidents (filter compromise) ==="
	@curl -s "http://localhost:8000/incidents?incident_type=compromise" | jq .

demo-spray:
	@echo "=== Running password spraying demo ==="
	python3 scripts/replay_auth_log.py -c 20 -m spray -a 198.51.100.77
	@echo "Waiting for spray monitor (up to 120s)..."
	@timeout 120 bash -c 'while true; do \
	  alert=$$(curl -s "http://localhost:9200/_plugins/_alerting/monitors/alerts?size=5" | jq -r ".alerts[] | select(.monitor_name==\"ssh-password-spraying\") | .state // \"none\""); \
	  if [[ "$$alert" == "ACTIVE" ]]; then echo "Spray monitor ACTIVE"; break; fi; \
	  sleep 3; done' || true
	@echo "=== Incidents (filter spraying) ==="
	@curl -s "http://localhost:8000/incidents?incident_type=spraying" | jq .

reset:
	@echo "=== Resetting environment (volumes + auth.log) ==="
	$(COMPOSE) down -v --remove-orphans
	@docker rm -f siem-portal-frontend 2>/dev/null || true
	@truncate -s 0 data/fluent-bit/auth.log 2>/dev/null || true
	@echo "Reset complete."

logs:
	$(COMPOSE) logs -f --tail=100