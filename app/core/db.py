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

CREATE TABLE IF NOT EXISTS integrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    name TEXT NOT NULL,
    kind TEXT NOT NULL,
    container_name TEXT,
    base_url TEXT NOT NULL,
    permission_mode TEXT NOT NULL DEFAULT 'MONITOR',
    credential_encrypted TEXT,
    settings_json TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_integrations_kind ON integrations(kind);
CREATE INDEX IF NOT EXISTS idx_integrations_container ON integrations(container_name);

CREATE TABLE IF NOT EXISTS activity_state (
    container_name TEXT PRIMARY KEY,
    last_active_at TEXT,
    last_checked_at TEXT,
    state TEXT,
    details_json TEXT
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


def get_activity_state(container_name: str):
    with connect() as conn:
        row = conn.execute(
            'SELECT * FROM activity_state WHERE container_name = ?',
            (container_name,),
        ).fetchone()
        return dict(row) if row else None


def upsert_activity_state(container_name: str, *, last_active_at, last_checked_at, state, details_json):
    with connect() as conn:
        conn.execute(
            '''
            INSERT INTO activity_state(container_name, last_active_at, last_checked_at, state, details_json)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(container_name) DO UPDATE SET
                last_active_at = excluded.last_active_at,
                last_checked_at = excluded.last_checked_at,
                state = excluded.state,
                details_json = excluded.details_json
            ''',
            (container_name, last_active_at, last_checked_at, state, details_json),
        )


def list_integrations_db():
    with connect() as conn:
        return [dict(row) for row in conn.execute(
            'SELECT * FROM integrations ORDER BY name COLLATE NOCASE'
        ).fetchall()]


def get_integration(integration_id: int):
    with connect() as conn:
        row = conn.execute(
            'SELECT * FROM integrations WHERE id = ?',
            (integration_id,),
        ).fetchone()
        return dict(row) if row else None


def upsert_integration(*, integration_id, name, kind, container_name, base_url,
                       permission_mode, credential_encrypted, settings_json, enabled):
    with connect() as conn:
        if integration_id:
            conn.execute(
                '''
                UPDATE integrations
                SET updated_at=CURRENT_TIMESTAMP,
                    name=?, kind=?, container_name=?, base_url=?, permission_mode=?,
                    credential_encrypted=?, settings_json=?, enabled=?
                WHERE id=?
                ''',
                (name, kind, container_name, base_url, permission_mode,
                 credential_encrypted, settings_json, enabled, integration_id),
            )
            return integration_id
        cur = conn.execute(
            '''
            INSERT INTO integrations(
                name, kind, container_name, base_url, permission_mode,
                credential_encrypted, settings_json, enabled
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (name, kind, container_name, base_url, permission_mode,
             credential_encrypted, settings_json, enabled),
        )
        return cur.lastrowid


def delete_integration(integration_id: int):
    with connect() as conn:
        conn.execute('DELETE FROM integrations WHERE id = ?', (integration_id,))
