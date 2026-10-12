import json
import logging
import re
import urllib.request
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request, Response, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Dict, Any, Optional, List
from pydantic import BaseModel

from app.database import (
    init_db,
    store_raw_webhook,
    save_or_update_incident,
    get_all_incidents,
    get_raw_webhooks,
    update_incident_status,
    get_incident_by_id,
    get_incidents_with_filters,
    get_ioc,
    get_all_iocs,
)

OPENSEARCH_URL = "http://opensearch:9200"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("portal-backend")

app = FastAPI(title="SIEM Security Portal Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
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

def fetch_all_active_alert_buckets(monitor_name: str, trigger_name: str) -> List[Dict[str, Any]]:
    """Fetch ALL active alerts for a monitor/trigger from OpenSearch to get all bucket keys."""
    buckets = []
    try:
        url = f"{OPENSEARCH_URL}/_plugins/_alerting/monitors/alerts?size=100"
        req_obj = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req_obj, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            alerts = data.get("alerts", [])
            for alert in alerts:
                if (alert.get("monitor_name") == monitor_name and 
                    alert.get("trigger_name") == trigger_name and
                    alert.get("state") == "ACTIVE"):
                    agg_content = alert.get("agg_alert_content", {})
                    bucket = agg_content.get("bucket", {})
                    bucket_keys = agg_content.get("bucket_keys", [])
                    if bucket_keys:
                        for bk in bucket_keys:
                            buckets.append({
                                "src_ip": bk,
                                "count": bucket.get("doc_count"),
                                "bucket_key": bucket.get("key", {}).get("src_ip"),
                            })
    except Exception as e:
        logger.warning("Failed to fetch alert details from OpenSearch: %s", e)
    return buckets


@app.post("/webhook/opensearch")
async def receive_opensearch_webhook(request: Request):
    raw_body = await request.body()
    raw_text = raw_body.decode("utf-8", errors="replace")

    print(
        f"\n================ [WEBHOOK RECEIVED] ================\n{raw_text}\n"
        "====================================================\n",
        flush=True,
    )
    logger.info("Received OpenSearch webhook payload (%d bytes)", len(raw_text))

    raw_id = store_raw_webhook(raw_text)

    monitor_name = None
    trigger_name = None
    severity = 1
    event_timestamp = None

    try:
        data = json.loads(raw_text)
        if isinstance(data, dict):
            monitor_name = data.get("monitor_name")
            trigger_name = data.get("trigger_name")
            severity = int(data.get("severity", 1)) if data.get("severity") else 1
            event_timestamp = (
                data.get("timestamp") or data.get("period_end") or data.get("alert_time")
            )
    except Exception as e:
        logger.warning("Could not parse payload as standard JSON: %s", e)

    incidents_created = []
    
    if monitor_name and trigger_name:
        buckets = fetch_all_active_alert_buckets(monitor_name, trigger_name)
        
        if buckets:
            for bucket in buckets:
                src_ip = bucket.get("src_ip") or bucket.get("bucket_key")
                count = bucket.get("count", 1)
                
                if not src_ip:
                    continue
                    
                incident = save_or_update_incident(
                    src_ip=src_ip,
                    severity=severity,
                    count=count,
                    event_timestamp=event_timestamp,
                    raw_payload=raw_text,
                )
                incidents_created.append(incident)
                logger.info(
                    "Incident recorded: ID=%s, src_ip=%s, severity=%s, count=%s",
                    incident["id"],
                    incident["src_ip"],
                    incident["severity"],
                    incident["count"],
                )
        else:
            src_ip = None
            count = 1
            try:
                data = json.loads(raw_text)
                if isinstance(data, dict):
                    src_ip = (
                        data.get("src_ip")
                        or data.get("bucket_key")
                        or data.get("attacker_ip")
                        or data.get("ip")
                    )
                    count_val = data.get("count")
                    count = int(count_val) if count_val not in (None, "") else 1
            except Exception:
                pass
            
            if not src_ip:
                ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw_text)
                if ip_match:
                    src_ip = ip_match.group(0)
            
            if not src_ip:
                src_ip = "unknown"
            
            incident = save_or_update_incident(
                src_ip=src_ip,
                severity=severity,
                count=count,
                event_timestamp=event_timestamp,
                raw_payload=raw_text,
            )
            incidents_created.append(incident)
            logger.info(
                "Incident recorded (fallback): ID=%s, src_ip=%s, severity=%s, count=%s",
                incident["id"],
                incident["src_ip"],
                incident["severity"],
                incident["count"],
            )
    else:
        src_ip = "unknown"
        incident = save_or_update_incident(
            src_ip=src_ip,
            severity=severity,
            count=1,
            event_timestamp=event_timestamp,
            raw_payload=raw_text,
        )
        incidents_created.append(incident)

    return {
        "status": "success",
        "raw_webhook_id": raw_id,
        "incidents_created": len(incidents_created),
        "incidents": incidents_created,
    }


# ─────────────────────────────────────────────
# Incident management endpoints
# ─────────────────────────────────────────────

@app.get("/incidents")
def list_incidents(
    status: Optional[str] = Query(None, description="Filter by status"),
    severity: Optional[int] = Query(None, description="Filter by severity"),
):
    incidents = get_incidents_with_filters(status=status, severity=severity)
    return {"total": len(incidents), "incidents": incidents}


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    row = get_incident_by_id(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    return row


class IncidentUpdate(BaseModel):
    status: str
    analyst_note: Optional[str] = None


@app.patch("/incidents/{incident_id}")
def update_incident(incident_id: int, update: IncidentUpdate):
    """Update incident status and/or analyst note. Status: open, investigating, resolved, blocked."""
    row = get_incident_by_id(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    allowed = {"open", "investigating", "resolved", "blocked"}
    if update.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid status. Allowed: {allowed}")
    
    updated = update_incident_status(incident_id, update.status, update.analyst_note)
    logger.info("Incident %s updated: status=%s, note=%s", incident_id, update.status, update.analyst_note)
    return {"status": update.status, "incident": updated}


# ─────────────────────────────────────────────
# Incident timeline (from OpenSearch)
# ─────────────────────────────────────────────

@app.get("/incidents/{incident_id}/timeline")
def get_incident_timeline(incident_id: int, limit: int = Query(50, ge=1, le=200)):
    """Get last N events from OpenSearch for the incident's src_ip."""
    incident = get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    
    src_ip = incident["src_ip"]
    if src_ip == "unknown":
        return {"incident_id": incident_id, "src_ip": src_ip, "events": [], "total": 0}
    
    try:
        now = datetime.now(timezone.utc)
        one_hour_ago = (now - timedelta(hours=1)).isoformat()
        
        query = {
            "size": limit,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"src_ip": src_ip}},
                        {"range": {"@timestamp": {"gte": one_hour_ago}}}
                    ]
                }
            }
        }
        
        url = f"{OPENSEARCH_URL}/security-logs/_search"
        req_obj = urllib.request.Request(
            url, 
            data=json.dumps(query).encode(),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req_obj, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            hits = data.get("hits", {}).get("hits", [])
            events = [h["_source"] for h in hits]
            total = data.get("hits", {}).get("total", {}).get("value", 0)
            
            return {
                "incident_id": incident_id,
                "src_ip": src_ip,
                "events": events,
                "total": total,
                "limit": limit,
            }
    except Exception as e:
        logger.error("Failed to fetch timeline from OpenSearch: %s", e)
        raise HTTPException(status_code=502, detail="Failed to fetch timeline from OpenSearch")


# ─────────────────────────────────────────────
# Stats endpoint
# ─────────────────────────────────────────────

@app.get("/stats")
def get_stats():
    """Get dashboard stats: counts by severity/status, top attackers, events per minute."""
    try:
        incidents = get_all_incidents()
        
        # By severity
        by_severity = {}
        for inc in incidents:
            sev = inc.get("severity", 1)
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        # By status
        by_status = {}
        for inc in incidents:
            st = inc.get("status", "open")
            by_status[st] = by_status.get(st, 0) + 1
        
        # Top attacker IPs
        ip_counts = {}
        for inc in incidents:
            ip = inc.get("src_ip", "unknown")
            ip_counts[ip] = ip_counts.get(ip, 0) + inc.get("count", 1)
        top_attackers = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        
        # Events per minute for last hour from OpenSearch
        events_per_minute = []
        try:
            now = datetime.now(timezone.utc)
            one_hour_ago = (now - timedelta(hours=1)).isoformat()
            
            query = {
                "size": 0,
                "query": {
                    "range": {"@timestamp": {"gte": one_hour_ago}}
                },
                "aggs": {
                    "events_per_minute": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "calendar_interval": "1m",
                            "format": "yyyy-MM-dd'T'HH:mm:ss"
                        }
                    }
                }
            }
            
            url = f"{OPENSEARCH_URL}/security-logs/_search"
            req_obj = urllib.request.Request(
                url,
                data=json.dumps(query).encode(),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req_obj, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                buckets = data.get("aggregations", {}).get("events_per_minute", {}).get("buckets", [])
                events_per_minute = [
                    {"timestamp": b["key_as_string"], "count": b["doc_count"]}
                    for b in buckets
                ]
        except Exception as e:
            logger.warning("Failed to fetch events per minute from OpenSearch: %s", e)
        
        return {
            "by_severity": by_severity,
            "by_status": by_status,
            "top_attackers": [{"ip": ip, "count": cnt} for ip, cnt in top_attackers],
            "events_per_minute": events_per_minute,
            "total_incidents": len(incidents),
        }
    except Exception as e:
        logger.error("Failed to compute stats: %s", e)
        raise HTTPException(status_code=500, detail="Failed to compute stats")


# ─────────────────────────────────────────────
# IOC endpoint
# ─────────────────────────────────────────────

@app.get("/api/ioc/{ip}")
def get_ioc_endpoint(ip: str):
    """Check if an IP is in the IOC list."""
    ioc = get_ioc(ip)
    if not ioc:
        return {
            "ip": ip,
            "malicious": False,
            "source": None,
            "metadata": None,
        }
    return {
        "ip": ioc["ip"],
        "malicious": bool(ioc["malicious"]),
        "source": ioc["source"],
        "metadata": json.loads(ioc["metadata"]) if ioc["metadata"] else None,
        "created_at": ioc["created_at"],
    }


@app.get("/api/iocs")
def list_iocs():
    """List all IOCs."""
    iocs = get_all_iocs()
    return {
        "total": len(iocs),
        "iocs": [
            {
                "ip": ioc["ip"],
                "malicious": bool(ioc["malicious"]),
                "source": ioc["source"],
                "metadata": json.loads(ioc["metadata"]) if ioc["metadata"] else None,
                "created_at": ioc["created_at"],
            }
            for ioc in iocs
        ],
    }


# ─────────────────────────────────────────────
# Legacy endpoints
# ─────────────────────────────────────────────

@app.post("/incidents/{incident_id}/block")
def block_incident(incident_id: int):
    row = get_incident_by_id(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    updated = update_incident_status(incident_id, "blocked")
    logger.info("Incident %s marked as BLOCKED (src_ip=%s)", incident_id, updated["src_ip"])
    return {"status": "blocked", "incident": updated}


@app.post("/incidents/{incident_id}/resolve")
def resolve_incident(incident_id: int):
    row = get_incident_by_id(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    updated = update_incident_status(incident_id, "resolved")
    logger.info("Incident %s marked as RESOLVED (src_ip=%s)", incident_id, updated["src_ip"])
    return {"status": "resolved", "incident": updated}


@app.post("/incidents/{incident_id}/reopen")
def reopen_incident(incident_id: int):
    row = get_incident_by_id(incident_id)
    if not row:
        raise HTTPException(status_code=404, detail="Incident not found")
    updated = update_incident_status(incident_id, "open")
    logger.info("Incident %s REOPENED (src_ip=%s)", incident_id, updated["src_ip"])
    return {"status": "open", "incident": updated}


@app.get("/webhook/raw")
def list_raw_webhooks():
    webhooks = get_raw_webhooks()
    return {"total": len(webhooks), "webhooks": webhooks}