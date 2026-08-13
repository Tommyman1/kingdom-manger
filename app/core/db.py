import sqlite3
from pathlib import Path
from .config import settings

SCHEMA = '''
CREATE TABLE IF NOT EXISTS container_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    observed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    container_id TEXT NOT NULL,
    name TEXT NOT NULL,
    image TEXT,
    status TEXT,
    health TEXT,
    cpu_percent REAL,
    memory_bytes INTEGER,
    rx_bytes INTEGER,
    tx_bytes INTEGER
);
CREATE INDEX IF NOT EXISTS idx_snapshots_container_time
ON container_snapshots(container_id, observed_at DESC);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    severity TEXT NOT NULL,
    source TEXT NOT NULL,
    container_name TEXT,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    payload TEXT
);

CREATE TABLE IF NOT EXISTS trusted_baselines (
    container_name TEXT PRIMARY KEY,
    captured_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    image TEXT,
    config_json TEXT NOT NULL
);
'''


def connect():
    path = Path(settings.database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with connect() as conn:
        conn.executescript(SCHEMA)
