import sqlite3
import datetime
import os
from typing import List, Dict, Any, Optional

DB_PATH = os.getenv("SQLITE_DB_PATH", "/app/data/incidents.db")


def get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS raw_webhooks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT NOT NULL,
            payload TEXT NOT NULL
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT NOT NULL,
            incident_type TEXT NOT NULL DEFAULT 'bruteforce',
            severity INTEGER NOT NULL,
            count INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            raw_payload TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            analyst_note TEXT
        );
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL UNIQUE,
            source TEXT NOT NULL,
            malicious BOOLEAN NOT NULL DEFAULT 1,
            metadata TEXT,
            created_at TEXT NOT NULL
        );
    """)
    # Seed IOCs
    seed_iocs = [
        ("203.0.113.42", "simulated feed", 1, '{"description": "Simulated brute-force attacker"}'),
        ("198.51.100.77", "simulated feed", 1, '{"description": "Simulated secondary attacker"}'),
    ]
    for ip, source, malicious, metadata in seed_iocs:
        cursor.execute(
            "INSERT OR IGNORE INTO iocs (ip, source, malicious, metadata, created_at) VALUES (?, ?, ?, ?, ?)",
            (ip, source, malicious, metadata, datetime.datetime.now(datetime.timezone.utc).isoformat())
        )
    conn.commit()
    conn.close()


def store_raw_webhook(payload: str) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute(
        "INSERT INTO raw_webhooks (received_at, payload) VALUES (?, ?)",
        (now_iso, payload)
    )
    webhook_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return webhook_id


def save_or_update_incident(src_ip: str, severity: int, count: int = 1, event_timestamp: Optional[str] = None, raw_payload: Optional[str] = None, incident_type: str = "bruteforce") -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now.isoformat()
    ts_str = event_timestamp or now_iso

    # Look for existing open incident for this src_ip and incident_type
    cursor.execute(
        "SELECT * FROM incidents WHERE src_ip = ? AND incident_type = ? ORDER BY last_seen DESC LIMIT 1",
        (src_ip, incident_type)
    )
    row = cursor.fetchone()

    if row:
        # Check if last_seen was within the last 10 minutes (600 seconds)
        try:
            last_dt = datetime.datetime.fromisoformat(row["last_seen"])
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=datetime.timezone.utc)
        except Exception:
            last_dt = now

        diff_seconds = (now - last_dt).total_seconds()
        if 0 <= diff_seconds <= 600:
            new_count = row["count"] + count
            cursor.execute(
                """
                UPDATE incidents
                SET count = ?, last_seen = ?, severity = ?, raw_payload = ?
                WHERE id = ?
                """,
                (new_count, now_iso, severity, raw_payload, row["id"])
            )
            conn.commit()
            cursor.execute("SELECT * FROM incidents WHERE id = ?", (row["id"],))
            updated_row = dict(cursor.fetchone())
            conn.close()
            return updated_row

    # Otherwise, create a new incident
    cursor.execute(
        """
        INSERT INTO incidents (src_ip, incident_type, severity, count, first_seen, last_seen, raw_payload, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, 'open')
        """,
        (src_ip, incident_type, severity, count, ts_str, now_iso, raw_payload)
    )
    incident_id = cursor.lastrowid
    conn.commit()
    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    new_row = dict(cursor.fetchone())
    conn.close()
    return new_row


def get_all_incidents() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents ORDER BY last_seen DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_raw_webhooks() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM raw_webhooks ORDER BY id DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def update_incident_status(incident_id: int, new_status: str, analyst_note: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Transition an incident to a new status (open | investigating | resolved | blocked)."""
    allowed = {"open", "investigating", "resolved", "blocked"}
    if new_status not in allowed:
        raise ValueError(f"Invalid status '{new_status}'. Allowed: {allowed}")
    conn = get_connection()
    cursor = conn.cursor()
    if analyst_note is not None:
        cursor.execute(
            "UPDATE incidents SET status = ?, analyst_note = ? WHERE id = ?",
            (new_status, analyst_note, incident_id),
        )
    else:
        cursor.execute(
            "UPDATE incidents SET status = ? WHERE id = ?",
            (new_status, incident_id),
        )
    conn.commit()
    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_incident_by_id(incident_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_incidents_with_filters(status: Optional[str] = None, severity: Optional[int] = None, incident_type: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    query = "SELECT * FROM incidents WHERE 1=1"
    params = []
    if status:
        query += " AND status = ?"
        params.append(status)
    if severity is not None:
        query += " AND severity = ?"
        params.append(severity)
    if incident_type:
        query += " AND incident_type = ?"
        params.append(incident_type)
    query += " ORDER BY last_seen DESC"
    cursor.execute(query, params)
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows


def get_ioc(ip: str) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM iocs WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_iocs() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM iocs ORDER BY created_at DESC")
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows
