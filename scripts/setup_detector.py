#!/usr/bin/env python3
"""
setup_detector.py  –  Stage 5 bootstrapper
==========================================
1. Create (or reuse) a Notifications webhook channel pointing to the
   portal-backend /webhook/opensearch endpoint.
2. Send a test notification to that channel and print the response.
3. Create (or reuse) the bucket-level monitor "ssh-bruteforce-by-ip".

Usage:
    python3 scripts/setup_detector.py [--opensearch http://localhost:9200]
                                      [--webhook-url http://portal-backend:8000/webhook/opensearch]
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request

# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def req(method: str, url: str, body: dict | None = None, *, label: str = ""):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json"}
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            raw = resp.read().decode()
            parsed = json.loads(raw) if raw else {}
            print(f"  ✔  {label or method + ' ' + url}  →  {resp.status}")
            return parsed
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {"raw": raw}
        print(f"  ✘  {label or method + ' ' + url}  →  HTTP {e.code}")
        print(f"     {json.dumps(parsed, indent=2)}")
        return {"_error": parsed, "_status": e.code}


def wait_opensearch(base: str, retries: int = 20, delay: float = 3.0):
    print(f"\n[*] Waiting for OpenSearch at {base} …")
    for i in range(retries):
        try:
            with urllib.request.urlopen(f"{base}/_cluster/health", timeout=5) as r:
                h = json.loads(r.read())
                if h.get("status") in ("green", "yellow"):
                    print(f"    Cluster status: {h['status']}")
                    return
        except Exception:
            pass
        time.sleep(delay)
        print(f"    retry {i+1}/{retries} …")
    print("ERROR: OpenSearch not reachable after retries", file=sys.stderr)
    sys.exit(1)


# ─────────────────────────────────────────────
# Step 1 – Notification channel
# ─────────────────────────────────────────────

def find_monitor_ids(base: str, name: str) -> list[str]:
    """Return every monitor ID with the given name.

    Notice: the Alerting API flattens monitor documents, while the underlying
    index stores the name under ``monitor.name``. Searching the top-level
    ``name`` field returns no hits, so match on the client side instead.
    """
    resp = req(
        "POST",
        f"{base}/_plugins/_alerting/monitors/_search",
        {"query": {"match_all": {}}, "size": 1000},
        label=f"Search monitors for {name}",
    )
    hits = (resp.get("hits") or {}).get("hits", [])
    ids = []
    for hit in hits:
        source = hit.get("_source", {})
        actual_name = source.get("name") or (source.get("monitor") or {}).get("name")
        if actual_name == name:
            ids.append(hit["_id"])
    return ids


def dedupe_monitors(base: str, name: str) -> str | None:
    """Delete duplicate monitors with the same name and return the survivor."""
    ids = find_monitor_ids(base, name)
    if not ids:
        return None

    keep = ids[0]
    for duplicate in ids[1:]:
        req(
            "DELETE",
            f"{base}/_plugins/_alerting/monitors/{duplicate}",
            label=f"Delete duplicate monitor {duplicate}",
        )
    if len(ids) > 1:
        print(f"    Removed {len(ids) - 1} duplicate monitor(s), keeping {keep}")
    return keep


def action_message_template() -> str:
    """Build the notification body for a bucket-level monitor.

    ``bucket_keys`` only exists inside ``ctx.newAlerts`` / ``ctx.dedupedAlerts``
    for bucket-level monitors. Joining with ``|`` lets the backend split the
    values even when one notification covers several buckets.
    """
    bucket_keys = (
        "{{#ctx.newAlerts}}{{{bucket_keys}}}|{{/ctx.newAlerts}}"
        "{{#ctx.dedupedAlerts}}{{{bucket_keys}}}|{{/ctx.dedupedAlerts}}"
    )
    return json.dumps({
        "monitor_name": "{{ctx.monitor.name}}",
        "trigger_name": "{{ctx.trigger.name}}",
        "severity": "{{ctx.trigger.severity}}",
        "bucket_keys": bucket_keys,
        "src_ip": bucket_keys,
        "period_end": "{{ctx.periodEnd}}",
    })


CHANNEL_NAME = "siem-portal-webhook"

def get_or_create_channel(base: str, webhook_url: str) -> str:
    """Return the channel_id of the SIEM portal webhook channel."""
    print(f"\n[1] Checking for existing notification channel '{CHANNEL_NAME}' …")

    # Search by name
    search_url = f"{base}/_plugins/_notifications/configs"
    resp = req("GET", search_url, label="GET notification configs")
    configs = resp.get("config_list", [])

    for cfg in configs:
        if cfg.get("config", {}).get("name") == CHANNEL_NAME:
            cid = cfg["config_id"]
            print(f"    Found existing channel  id={cid}")
            return cid

    # Create it
    print(f"    Creating webhook channel → {webhook_url}")
    body = {
        "config": {
            "name": CHANNEL_NAME,
            "description": "SIEM portal FastAPI webhook receiver",
            "config_type": "webhook",
            "is_enabled": True,
            "webhook": {
                "url": webhook_url,
                "method": "POST",
                "header_params": {"Content-Type": "application/json"},
            },
        }
    }
    result = req("POST", f"{base}/_plugins/_notifications/configs", body, label="Create channel")
    if "_error" in result:
        print("FATAL: could not create notification channel", file=sys.stderr)
        sys.exit(1)
    cid = result.get("config_id") or result.get("_id")
    print(f"    Created channel  id={cid}")
    return cid


# ─────────────────────────────────────────────
# Step 2 – Test notification
# ─────────────────────────────────────────────

def test_channel(base: str, channel_id: str):
    print(f"\n[2] Sending test notification to channel {channel_id} …")
    url = f"{base}/_plugins/_notifications/feature/test/{channel_id}"
    resp = req("GET", url, label="Test notification")
    if "_error" in resp:
        print("    ⚠  Test notification failed – raw error shown above.")
        print("    ⚠  Continuing anyway (channel may still work for monitor actions).")
    else:
        print("    Test notification delivered successfully.")


# ─────────────────────────────────────────────
# Step 3 – Bucket-level monitor
# ─────────────────────────────────────────────

MONITOR_NAME = "ssh-bruteforce-by-ip"

def get_or_create_monitor(base: str, channel_id: str):
    print(f"\n[3] Checking for existing monitor '{MONITOR_NAME}' …")

    mid = dedupe_monitors(base, MONITOR_NAME)
    if mid:
        print(f"    Found existing monitor  id={mid}")
    action_message = action_message_template()

    monitor_body = {
        "type": "monitor",
        "name": MONITOR_NAME,
        "monitor_type": "bucket_level_monitor",
        "enabled": True,
        "schedule": {
            "period": {"interval": 1, "unit": "MINUTES"}
        },
        "inputs": [
            {
                "search": {
                    "indices": ["security-logs"],
                    "query": {
                        "size": 0,
                        "query": {
                            "bool": {
                                "filter": [
                                    {
                                        "term": {
                                            "event_action": "failed_login"
                                        }
                                    },
                                    {
                                        "range": {
                                            "@timestamp": {
                                                "gte": "now-5m",
                                                "lte": "now"
                                            }
                                        }
                                    }
                                ]
                            }
                        },
                        "aggregations": {
                            "composite_agg": {
                                "composite": {
                                    "sources": [
                                        {
                                            "src_ip": {
                                                "terms": {
                                                    "field": "src_ip"
                                                }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        ],
        "triggers": [
            {
                "bucket_level_trigger": {
                    "name": "brute-force-threshold",
                    "severity": "1",
                    "condition": {
                        "buckets_path": {
                            "_count": "_count"
                        },
                        "parent_bucket_path": "composite_agg",
                        "script": {
                            "source": "params._count > 5",
                            "lang": "painless"
                        }
                    },
                    "actions": [
                        {
                            "name": "notify-portal",
                            "destination_id": channel_id,
                            "message_template": {
                                "source": action_message
                            },
                            "throttle_enabled": False,
                        }
                    ]
                }
            }
        ]
    }

    if mid:
        print(f"    Updating monitor {mid} …")
        result = req(
            "PUT",
            f"{base}/_plugins/_alerting/monitors/{mid}",
            monitor_body,
            label="Update monitor",
        )
    else:
        print(f"    Creating bucket-level monitor …")
        result = req(
            "POST",
            f"{base}/_plugins/_alerting/monitors",
            monitor_body,
            label="Create monitor",
        )

    if "_error" in result:
        print("FATAL: could not create/update monitor", file=sys.stderr)
        sys.exit(1)

    mid = result.get("_id") or mid
    print(f"    Saved monitor  id={mid}")
    return mid


def create_monitor(base: str, channel_id: str, name: str, monitor_body: dict):
    """Create or update a monitor by exact name."""
    print(f"\n[+] Ensuring monitor '{name}' …")
    mid = dedupe_monitors(base, name)
    if mid:
        print(f"    Found existing monitor  id={mid}")
    if mid:
        print(f"    Updating monitor {mid} …")
        result = req("PUT", f"{base}/_plugins/_alerting/monitors/{mid}", monitor_body, label=f"Update monitor {name}")
    else:
        print(f"    Creating monitor {name} …")
        result = req("POST", f"{base}/_plugins/_alerting/monitors", monitor_body, label=f"Create monitor {name}")
    if "_error" in result:
        print(f"FATAL: could not create/update monitor {name}", file=sys.stderr)
        sys.exit(1)
    mid = result.get("_id") or mid
    print(f"    Saved monitor {name}  id={mid}")
    return mid


# Monitor: ssh-bruteforce-then-success
def build_compromise_monitor(channel_id: str) -> dict:
    action_message = action_message_template()
    return {
        "type": "monitor",
        "name": "ssh-bruteforce-then-success",
        "monitor_type": "bucket_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [{
            "search": {
                "indices": ["security-logs"],
                "query": {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [
                                {"range": {"@timestamp": {"gte": "now-10m", "lte": "now"}}}
                            ]
                        }
                    },
                    "aggregations": {
                        "by_ip": {
                            "composite": {
                                "sources": [{"src_ip": {"terms": {"field": "src_ip"}}}],
                                "size": 100
                            },
                            "aggregations": {
                                "failed": {"filter": {"term": {"event_action": "failed_login"}}},
                                "success": {"filter": {"term": {"event_action": "accepted_login"}}}
                            }
                        }
                    }
                }
            }
        }],
        "triggers": [{
            "bucket_level_trigger": {
                "name": "compromise-threshold",
                "severity": "1",
                "condition": {
                    "buckets_path": {
                        "failed": "failed._count",
                        "success": "success._count"
                    },
                    "parent_bucket_path": "by_ip",
                    "script": {
                        "source": "params.failed > 5 && params.success > 0",
                        "lang": "painless"
                    }
                },
                "actions": [{
                    "name": "notify-portal",
                    "destination_id": channel_id,
                    "message_template": {"source": action_message},
                    "throttle_enabled": False
                }]
            }
        }]
    }


# Monitor: ssh-password-spraying
def build_spray_monitor(channel_id: str) -> dict:
    action_message = action_message_template()
    return {
        "type": "monitor",
        "name": "ssh-password-spraying",
        "monitor_type": "bucket_level_monitor",
        "enabled": True,
        "schedule": {"period": {"interval": 1, "unit": "MINUTES"}},
        "inputs": [{
            "search": {
                "indices": ["security-logs"],
                "query": {
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [
                                {"term": {"event_action": "failed_login"}},
                                {"range": {"@timestamp": {"gte": "now-10m", "lte": "now"}}}
                            ]
                        }
                    },
                    "aggregations": {
                        "by_ip": {
                            "composite": {
                                "sources": [{"src_ip": {"terms": {"field": "src_ip"}}}],
                                "size": 100
                            },
                            "aggregations": {
                                "unique_users": {"cardinality": {"field": "user"}}
                            }
                        }
                    }
                }
            }
        }],
        "triggers": [{
            "bucket_level_trigger": {
                "name": "spray-threshold",
                "severity": "2",
                "condition": {
                    "buckets_path": {"users": "unique_users"},
                    "parent_bucket_path": "by_ip",
                    "script": {"source": "params.users > 5", "lang": "painless"}
                },
                "actions": [{
                    "name": "notify-portal",
                    "destination_id": channel_id,
                    "message_template": {"source": action_message},
                    "throttle_enabled": False
                }]
            }
        }]
    }


# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SIEM Stage-5 detector setup")
    parser.add_argument(
        "--opensearch",
        default="http://localhost:9200",
        help="OpenSearch base URL (default: http://localhost:9200)",
    )
    parser.add_argument(
        "--webhook-url",
        default="http://portal-backend:8000/webhook/opensearch",
        help="Webhook URL reachable FROM OpenSearch container",
    )
    args = parser.parse_args()

    base = args.opensearch.rstrip("/")
    webhook_url = args.webhook_url

    print("=" * 60)
    print("  SIEM Stage 5 – Detector Setup")
    print(f"  OpenSearch : {base}")
    print(f"  Webhook URL: {webhook_url}")
    print("=" * 60)

    wait_opensearch(base)

    channel_id = get_or_create_channel(base, webhook_url)
    test_channel(base, channel_id)
    monitor_id = get_or_create_monitor(base, channel_id)

    # Additional monitors
    create_monitor(base, channel_id, "ssh-bruteforce-then-success", build_compromise_monitor(channel_id))
    create_monitor(base, channel_id, "ssh-password-spraying", build_spray_monitor(channel_id))

    print("\n" + "=" * 60)
    print("  Done!")
    print(f"  Channel ID : {channel_id}")
    print(f"  Monitor ID : {monitor_id}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
