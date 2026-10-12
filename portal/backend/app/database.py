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
            severity INTEGER NOT NULL,
            count INTEGER NOT NULL DEFAULT 1,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            raw_payload TEXT,
            status TEXT NOT NULL DEFAULT 'open'
        );
    """)
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


def save_or_update_incident(src_ip: str, severity: int, count: int = 1, event_timestamp: Optional[str] = None, raw_payload: Optional[str] = None) -> Dict[str, Any]:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now.isoformat()
    ts_str = event_timestamp or now_iso

    # Look for existing open incident for this src_ip
    cursor.execute(
        "SELECT * FROM incidents WHERE src_ip = ? ORDER BY last_seen DESC LIMIT 1",
        (src_ip,)
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
        INSERT INTO incidents (src_ip, severity, count, first_seen, last_seen, raw_payload, status)
        VALUES (?, ?, ?, ?, ?, ?, 'open')
        """,
        (src_ip, severity, count, ts_str, now_iso, raw_payload)
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


def update_incident_status(incident_id: int, new_status: str) -> Optional[Dict[str, Any]]:
    """Transition an incident to a new status (open | blocked | resolved)."""
    allowed = {"open", "blocked", "resolved"}
    if new_status not in allowed:
        raise ValueError(f"Invalid status '{new_status}'. Allowed: {allowed}")
    conn = get_connection()
    cursor = conn.cursor()
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
