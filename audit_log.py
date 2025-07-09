import sqlite3
from datetime import datetime
from database import get_db_connection

def log_event(username, event_description, success=True):
    """
    Logs an event to the audit log database.
    """
    conn = get_db_connection()
    try:
        timestamp = datetime.now().isoformat()
        status = "SUCCESS" if success else "FAILED"
        conn.execute("INSERT INTO audit_log (username, timestamp, event_description, status) VALUES (?, ?, ?, ?)",
                     (username, timestamp, event_description, status))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Error logging event: {e}")
    finally:
        conn.close()

def get_audit_logs(limit=100):
    """
    Retrieves recent audit logs. (For future admin features)
    """
    conn = get_db_connection()
    try:
        logs = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
        return logs
    except sqlite3.Error as e:
        print(f"Error retrieving audit logs: {e}")
        return []
    finally:
        conn.close()