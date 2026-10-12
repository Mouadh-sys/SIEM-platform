import json
import logging
import re
import urllib.request
from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, Optional

from app.database import (
    init_db,
    store_raw_webhook,
    save_or_update_incident,
    get_all_incidents,
    get_raw_webhooks,
    update_incident_status,
    get_incident_by_id,
)

OPENSEARCH_URL = "http://opensearch:9200"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("portal-backend")

app = FastAPI(title="SIEM Security Portal Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()
    logger.info("Initialized SQLite database for SIEM incidents.")


@app.get("/health")
def health_check():
    return {"status": "ok", "service": "portal-backend"}


# ─────────────────────────────────────────────
# Webhook receiver (OpenSearch → portal)
# ─────────────────────────────────────────────

def fetch_alert_details(monitor_name: str, trigger_name: str) -> Optional[Dict[str, Any]]:
    """Fetch the latest alert for a monitor/trigger from OpenSearch to get bucket keys."""
    try:
        url = f"{OPENSEARCH_URL}/_plugins/_alerting/monitors/alerts?size=1"
        req_obj = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req_obj, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            alerts = data.get("alerts", [])
            for alert in alerts:
                if alert.get("monitor_name") == monitor_name and alert.get("trigger_name") == trigger_name:
                    agg_content = alert.get("agg_alert_content", {})
                    bucket = agg_content.get("bucket", {})
                    bucket_keys = agg_content.get("bucket_keys", [])
                    return {
                        "src_ip": bucket_keys[0] if bucket_keys else None,
                        "count": bucket.get("doc_count"),
                        "bucket_key": bucket.get("key", {}).get("src_ip"),
                    }
    except Exception as e:
        logger.warning("Failed to fetch alert details from OpenSearch: %s", e)
    return None


@app.post("/webhook/opensearch")
async def receive_opensearch_webhook(request: Request):
    # 1. Always read and store the raw body first
    raw_body = await request.body()
    raw_text = raw_body.decode("utf-8", errors="replace")

    print(
        f"\n================ [WEBHOOK RECEIVED] ================\n{raw_text}\n"
        "====================================================\n",
        flush=True,
    )
    logger.info("Received OpenSearch webhook payload (%d bytes)", len(raw_text))

    raw_id = store_raw_webhook(raw_text)

    # 2. Parse the payload
    src_ip = None
    severity = 1
    count = 1
    event_timestamp = None

    try:
        data = json.loads(raw_text)
        if isinstance(data, dict):
            src_ip = (
                data.get("src_ip")
                or data.get("bucket_key")
                or data.get("attacker_ip")
                or data.get("ip")
            )

            if not src_ip and "action" in data and isinstance(data["action"], dict):
                src_ip = data["action"].get("src_ip") or data["action"].get("bucket_key")

            if not src_ip and "bucket_keys" in data:
                bkeys = data["bucket_keys"]
                if isinstance(bkeys, list) and len(bkeys) > 0:
                    src_ip = str(bkeys[0])
                elif isinstance(bkeys, str):
                    src_ip = bkeys

            severity = int(data.get("severity", 1)) if data.get("severity") else 1
            count_val = data.get("count")
            count = int(count_val) if count_val not in (None, "") else 1
            event_timestamp = (
                data.get("timestamp") or data.get("period_end") or data.get("alert_time")
            )

            # If src_ip still not found, try fetching from OpenSearch alerts
            if not src_ip or src_ip == "unknown":
                monitor_name = data.get("monitor_name")
                trigger_name = data.get("trigger_name")
                if monitor_name and trigger_name:
                    alert_details = fetch_alert_details(monitor_name, trigger_name)
                    if alert_details:
                        src_ip = alert_details.get("src_ip") or alert_details.get("bucket_key")
                        if alert_details.get("count"):
                            count = alert_details["count"]

    except Exception as e:
        logger.warning("Could not parse payload as standard JSON: %s", e)

    # Fallback: regex search for IPv4 in raw payload
    if not src_ip:
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_text)
        if ip_match:
            src_ip = ip_match.group(0)

    if not src_ip:
        src_ip = "unknown"

    # 3. Dedupe & Save Incident
    incident = save_or_update_incident(
        src_ip=src_ip,
        severity=severity,
        count=count,
        event_timestamp=event_timestamp,
        raw_payload=raw_text,
    )

    logger.info(
        "Incident recorded: ID=%s, src_ip=%s, severity=%s, count=%s",
        incident["id"],
        incident["src_ip"],
        incident["severity"],
        incident["count"],
    )

    return {
        "status": "success",
        "raw_webhook_id": raw_id,
        "incident": incident,
    }


# ─────────────────────────────────────────────
# Incident management
# ─────────────────────────────────────────────

@app.get("/incidents")
def list_incidents():
    incidents = get_all_incidents()
    return {"total": len(incidents), "incidents": incidents}


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    row = get_incident_by_id(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


@app.post("/incidents/{incident_id}/block")
def block_incident(incident_id: int):
    """Mark an incident as blocked (simulates IP block action)."""
    row = get_incident_by_id(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    updated = update_incident_status(incident_id, "blocked")
    logger.info("Incident %s marked as BLOCKED (src_ip=%s)", incident_id, updated["src_ip"])
    return {"status": "blocked", "incident": updated}


@app.post("/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: int):
    """Mark an incident as resolved."""
    row = get_incident_by_id(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    updated = update_incident_status(incident_id, "resolved")
    logger.info("Incident %s marked as RESOLVED (src_ip=%s)", incident_id, updated["src_ip"])
    return {"status": "resolved", "incident": updated}


@app.post("/incidents/{incident_id}/reopen")
def reopen_incident(incident_id: int):
    """Reopen a previously blocked or resolved incident."""
    row = get_incident_by_id(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    updated = update_incident_status(incident_id, "open")
    logger.info("Incident %s REOPENED (src_ip=%s)", incident_id, updated["src_ip"])
    return {"status": "open", "incident": updated}


# ─────────────────────────────────────────────
# Raw webhook inspection
# ─────────────────────────────────────────────

@app.get("/webhook/raw")
def list_raw_webhooks():
    webhooks = get_raw_webhooks()
    return {"total": len(webhooks), "webhooks": webhooks}
