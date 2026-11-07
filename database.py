import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "siem.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source TEXT NOT NULL,
            event_type TEXT NOT NULL,
            username TEXT DEFAULT '',
            source_ip TEXT DEFAULT '',
            details TEXT DEFAULT '',
            risk_score INTEGER DEFAULT 0
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id INTEGER NOT NULL,
            severity TEXT NOT NULL,
            reason TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            created_at TEXT NOT NULL,
            FOREIGN KEY(event_id) REFERENCES events(id)
        )""")
        db.commit()
