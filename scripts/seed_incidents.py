#!/usr/bin/env python3
"""
seed_incidents.py - Create fake historical incidents for dashboard demo
"""
import sqlite3
import datetime
import os
import random

DB_PATH = os.getenv("SQLITE_DB_PATH", "/app/data/incidents.db")

ATTACKER_IPS = [
    "203.0.113.42", "198.51.100.77", "192.0.2.14", "203.0.113.89",
    "198.51.100.23", "203.0.113.156", "192.0.2.67", "198.51.100.201",
]

STATUSES = ["open", "investigating", "resolved", "blocked"]
SEVERITIES = [1, 2, 3, 4]

def seed():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Clear existing incidents (optional - comment out to keep real ones)
    cursor.execute("DELETE FROM incidents")
    
    now = datetime.datetime.now(datetime.timezone.utc)
    
    for i in range(30):
        ip = random.choice(ATTACKER_IPS)
        severity = random.choice(SEVERITIES)
        status = random.choice(STATUSES)
        count = random.randint(5, 200)
        
        # Spread over last 7 days
        days_ago = random.randint(0, 7)
        hours_ago = random.randint(0, 23)
        minutes_ago = random.randint(0, 59)
        first_seen = now - datetime.timedelta(days=days_ago, hours=hours_ago, minutes=minutes_ago)
        last_seen = first_seen + datetime.timedelta(minutes=random.randint(5, 120))
        
        analyst_notes = [
            None,
            "Investigating source network",
            "Confirmed brute-force attack, blocking at firewall",
            "False positive - authorized scanner",
            "Escalated to SOC team",
            "Auto-resolved after IP block",
        ]
        
        cursor.execute("""
            INSERT INTO incidents (src_ip, severity, count, first_seen, last_seen, raw_payload, status, analyst_note)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ip,
            severity,
            count,
            first_seen.isoformat(),
            last_seen.isoformat(),
            f'{{"monitor_name": "ssh-bruteforce-by-ip", "trigger_name": "brute-force-threshold", "severity": "{severity}", "src_ip": "{ip}", "count": "{count}", "period_end": "{last_seen.isoformat()}"}}',
            status,
            random.choice(analyst_notes),
        ))
    
    conn.commit()
    conn.close()
    print(f"Seeded 30 historical incidents across {len(ATTACKER_IPS)} attacker IPs")

if __name__ == "__main__":
    seed()