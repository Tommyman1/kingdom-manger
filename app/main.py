from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote
from zoneinfo import ZoneInfo

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse

VERSION = "3.1.3"
app = FastAPI(title="Kingdom Manager", version=VERSION)

DOCKER = os.getenv("DOCKER_HOST", "tcp://docker-socket-proxy:2375").replace("tcp://", "http://")
DATA_DIR = Path(os.getenv("KM_DATA_DIR", "/data"))
DB_PATH = DATA_DIR / "kingdom.db"
API_TOKEN = os.getenv("KM_API_TOKEN", "")
TZ = ZoneInfo(os.getenv("TZ", "America/New_York"))
QUARANTINE_NETWORK = os.getenv("KM_QUARANTINE_NETWORK", "kingdom-quarantine")
TRIVY_RUNNER = os.getenv("TRIVY_RUNNER", "kingdom-manager-trivy")
TRIVY_EXEC_DOCKER = os.getenv("TRIVY_EXEC_DOCKER_HOST", "tcp://trivy-exec-proxy:2375").replace("tcp://", "http://")
DOCKER_CACHE_TTL_SECONDS = float(os.getenv("KM_DOCKER_CACHE_TTL_SECONDS", "12"))
DOCKER_CACHE_MAX_STALE_SECONDS = float(os.getenv("KM_DOCKER_CACHE_MAX_STALE_SECONDS", "300"))
SENSOR_CACHE_TTL_SECONDS = float(os.getenv("KM_SENSOR_CACHE_TTL_SECONDS", "15"))
API_SNAPSHOT_TTL_SECONDS = float(os.getenv("KM_API_SNAPSHOT_TTL_SECONDS", "10"))
DASHBOARD_SNAPSHOT_PATH = DATA_DIR / "dashboard_snapshot.json"
DASHBOARD_REFRESH_SECONDS = float(os.getenv("KM_DASHBOARD_REFRESH_SECONDS", "15"))
MONITOR_SCHEDULER_OFFSET_SECONDS = int(os.getenv("KM_MONITOR_SCHEDULER_OFFSET_SECONDS", "20"))
SCORE_SCHEDULER_OFFSET_SECONDS = int(os.getenv("KM_SCORE_SCHEDULER_OFFSET_SECONDS", "120"))
TRIVY_SCHEDULER_OFFSET_SECONDS = int(os.getenv("KM_TRIVY_SCHEDULER_OFFSET_SECONDS", "420"))
DRIFT_SCHEDULER_OFFSET_SECONDS = int(os.getenv("KM_DRIFT_SCHEDULER_OFFSET_SECONDS", "1140"))
SENSOR_SCHEDULER_OFFSET_SECONDS = int(os.getenv("KM_SENSOR_SCHEDULER_OFFSET_SECONDS", "45"))
CHECK_SECONDS = int(os.getenv("KM_CHECK_SECONDS", "300"))
IDLE_CPU = float(os.getenv("KM_IDLE_CPU_PERCENT", "3.0"))
IDLE_MINUTES = int(os.getenv("KM_IDLE_MINUTES", "20"))
DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK_URL", "")
N8N_WEBHOOK = os.getenv("N8N_WEBHOOK_URL", "")
CLAMAV_HOST = os.getenv("CLAMAV_HOST", "clamav")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
CROWDSEC_URL = os.getenv("CROWDSEC_URL", "")
CROWDSEC_API_KEY = os.getenv("CROWDSEC_API_KEY", "")
FALCO_WEBHOOK_SECRET = os.getenv("FALCO_WEBHOOK_SECRET", "")
DECISION_WINDOW_SECONDS = int(os.getenv("KM_DECISION_WINDOW_SECONDS", "900"))
DECISION_DEBOUNCE_SECONDS = int(os.getenv("KM_DECISION_DEBOUNCE_SECONDS", "120"))
TRIVY_CONTEXT_SECONDS = int(os.getenv("KM_TRIVY_CONTEXT_SECONDS", "604800"))
FALCO_HOST = os.getenv("FALCO_HOST", "falco")
FALCO_HEALTH_PORT = int(os.getenv("FALCO_HEALTH_PORT", "8765"))
TRIVY_AUTO_SCAN_ENABLED = os.getenv("TRIVY_AUTO_SCAN_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
TRIVY_AUTO_SCAN_EVERY_SECONDS = int(os.getenv("TRIVY_AUTO_SCAN_EVERY_SECONDS", "1800"))
TRIVY_AUTO_SCAN_START_DELAY_SECONDS = int(os.getenv("TRIVY_AUTO_SCAN_START_DELAY_SECONDS", "45"))
TRIVY_RESCAN_SECONDS = int(os.getenv("TRIVY_RESCAN_SECONDS", "604800"))
RECOVERY_DOCKER = os.getenv("RECOVERY_DOCKER_HOST", "tcp://recovery-socket-proxy:2375").replace("tcp://", "http://")
RECOVERY_APPROVAL_TTL = int(os.getenv("KM_RECOVERY_APPROVAL_TTL_SECONDS", "900"))
RECOVERY_OBSERVATION_SECONDS = int(os.getenv("KM_RECOVERY_OBSERVATION_SECONDS", "30"))
RECOVERY_BLOCK_ON_CRITICAL_CVE = os.getenv("KM_RECOVERY_BLOCK_ON_CRITICAL_CVE", "true").lower() in {"1","true","yes","on"}
RECOVERY_ALLOW_DATABASES = os.getenv("KM_RECOVERY_ALLOW_DATABASES", "false").lower() in {"1","true","yes","on"}
NOTIFY_MIN_SEVERITY = os.getenv("KM_NOTIFY_MIN_SEVERITY", "high").lower()
DAILY_REPORT_ENABLED = os.getenv("KM_DAILY_REPORT_ENABLED", "true").lower() in {"1","true","yes","on"}
DAILY_REPORT_HOUR = int(os.getenv("KM_DAILY_REPORT_HOUR", "8"))
WEEKLY_REPORT_WEEKDAY = int(os.getenv("KM_WEEKLY_REPORT_WEEKDAY", "0"))
WEEKLY_REPORT_HOUR = int(os.getenv("KM_WEEKLY_REPORT_HOUR", "9"))
SCORE_HISTORY_INTERVAL_SECONDS = int(os.getenv("KM_SCORE_HISTORY_INTERVAL_SECONDS", "900"))
BASELINE_DAYS = int(os.getenv("KM_BASELINE_DAYS", "7"))
BASELINE_STABLE_MIN_EVENTS = int(os.getenv("KM_BASELINE_STABLE_MIN_EVENTS", "100"))
BASELINE_STABLE_MIN_HOURS = int(os.getenv("KM_BASELINE_STABLE_MIN_HOURS", "12"))
BASELINE_STABLE_ATTENUATION = int(os.getenv("KM_BASELINE_STABLE_ATTENUATION", "20"))
BASELINE_LEARNING_ATTENUATION = int(os.getenv("KM_BASELINE_LEARNING_ATTENUATION", "8"))
KNOWN_GOOD_RESIDUAL_RISK = int(os.getenv("KM_KNOWN_GOOD_RESIDUAL_RISK", "5"))
KNOWN_GOOD_MAX_ATTENUATION = int(os.getenv("KM_KNOWN_GOOD_MAX_ATTENUATION", "45"))
SENSOR_FAILURE_GRACE_SECONDS = int(os.getenv("KM_SENSOR_FAILURE_GRACE_SECONDS", "120"))
PLAYBOOKS_ENABLED = os.getenv("KM_PLAYBOOKS_ENABLED", "true").lower() in {"1","true","yes","on"}
PLAYBOOK_AUTO_EVIDENCE = os.getenv("KM_PLAYBOOK_AUTO_EVIDENCE", "true").lower() in {"1","true","yes","on"}
PLAYBOOK_AUTO_SCAN = os.getenv("KM_PLAYBOOK_AUTO_SCAN", "true").lower() in {"1","true","yes","on"}
PLAYBOOK_AUTO_ISOLATE = os.getenv("KM_PLAYBOOK_AUTO_ISOLATE", "false").lower() in {"1","true","yes","on"}
PLAYBOOK_AUTO_RECOVER = os.getenv("KM_PLAYBOOK_AUTO_RECOVER", "false").lower() in {"1","true","yes","on"}
IGNORE_HTTP_TRANSPORT_ERRORS = os.getenv("KM_IGNORE_HTTP_TRANSPORT_ERRORS", "true").lower() in {"1","true","yes","on"}
UPDATE_ENGINE_ENABLED = os.getenv("KM_UPDATE_ENGINE_ENABLED", "true").lower() in {"1","true","yes","on"}
UPDATE_CHECK_SECONDS = int(os.getenv("KM_UPDATE_CHECK_SECONDS", "21600"))
UPDATE_START_DELAY_SECONDS = int(os.getenv("KM_UPDATE_START_DELAY_SECONDS", "180"))
UPDATE_OBSERVATION_SECONDS = int(os.getenv("KM_UPDATE_OBSERVATION_SECONDS", "60"))
UPDATE_REQUIRE_TRIVY = os.getenv("KM_UPDATE_REQUIRE_TRIVY", "true").lower() in {"1","true","yes","on"}
UPDATE_BLOCK_CRITICAL = os.getenv("KM_UPDATE_BLOCK_CRITICAL_CVE", "true").lower() in {"1","true","yes","on"}
UPDATE_BLOCK_HIGH = os.getenv("KM_UPDATE_BLOCK_HIGH_CVE", "false").lower() in {"1","true","yes","on"}
UPDATE_AUTO_APPLY = os.getenv("KM_UPDATE_AUTO_APPLY", "false").lower() in {"1","true","yes","on"}
UPDATE_ALLOW_STATEFUL = os.getenv("KM_UPDATE_ALLOW_STATEFUL", "false").lower() in {"1","true","yes","on"}
ROLLBACK_RETENTION = int(os.getenv("KM_ROLLBACK_RETENTION", "10"))
PORTAINER_URL = os.getenv("PORTAINER_URL", "").rstrip('/')
PORTAINER_API_KEY = os.getenv("PORTAINER_API_KEY", "")
PORTAINER_STACK_ID = os.getenv("PORTAINER_STACK_ID", "")
COMPOSE_SNAPSHOT_PATH = os.getenv("KM_COMPOSE_SNAPSHOT_PATH", "")
DASHBOARD_URL = os.getenv("KM_DASHBOARD_URL", "https://kingdom-manager-tail.kingdom.local").rstrip("/")
DISCORD_ROLE_ID = os.getenv("DISCORD_MENTION_ROLE_ID", "").strip()
DISCORD_NOTIFY_UPDATES = os.getenv("DISCORD_NOTIFY_UPDATES", "true").lower() in {"1","true","yes","on"}
DISCORD_NOTIFY_RECOVERY = os.getenv("DISCORD_NOTIFY_RECOVERY", "true").lower() in {"1","true","yes","on"}
DISCORD_NOTIFY_SENSOR_FAILURES = os.getenv("DISCORD_NOTIFY_SENSOR_FAILURES", "true").lower() in {"1","true","yes","on"}
DRIFT_SCAN_ENABLED = os.getenv("KM_DRIFT_SCAN_ENABLED", "true").lower() in {"1","true","yes","on"}
DRIFT_SCAN_SECONDS = int(os.getenv("KM_DRIFT_SCAN_SECONDS", "1800"))
BACKUP_MAX_AGE_HOURS = int(os.getenv("KM_BACKUP_MAX_AGE_HOURS", "48"))
AUTO_SAFE_PLAYBOOKS = os.getenv("KM_AUTO_SAFE_PLAYBOOKS", "true").lower() in {"1","true","yes","on"}
SCHEMA_VERSION = 15

DATA_DIR.mkdir(parents=True, exist_ok=True)


def conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH, timeout=30)
    c.row_factory = sqlite3.Row
    return c


def _backup_database(label: str) -> str | None:
    if not DB_PATH.exists() or DB_PATH.stat().st_size == 0:
        return None
    dest = DATA_DIR / f"kingdom.db.backup-{label}-{int(time.time())}"
    src = sqlite3.connect(DB_PATH)
    dst = sqlite3.connect(dest)
    try:
        src.backup(dst)
    finally:
        dst.close(); src.close()
    return str(dest)


def _ensure_column(c: sqlite3.Connection, table: str, name: str, decl: str) -> None:
    cols = {r[1] for r in c.execute(f"PRAGMA table_info({table})")}
    if name not in cols:
        c.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")


def _migrate_events_if_needed() -> None:
    with conn() as c:
        exists = c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='events'").fetchone()
        if not exists:
            return
        info = c.execute("PRAGMA table_info(events)").fetchall()
        cols = {r[1] for r in info}
        required = {"id","ts","kind","subject","detail","severity"}
        legacy_required = [r[1] for r in info if r[1] not in required and int(r[3] or 0) == 1 and r[4] is None]
        if required.issubset(cols) and not legacy_required:
            return
    backup = _backup_database(f"pre-schema-v{SCHEMA_VERSION}")
    with conn() as c:
        info = c.execute("PRAGMA table_info(events)").fetchall()
        cols = {r[1] for r in info}
        legacy = f"events_legacy_v{SCHEMA_VERSION}_{int(time.time())}"
        c.execute(f"ALTER TABLE events RENAME TO {legacy}")
        c.execute("""CREATE TABLE events(
          id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
          kind TEXT NOT NULL, subject TEXT, detail TEXT, severity TEXT DEFAULT 'info'
        )""")
        def col(name: str, fallback: str = "NULL") -> str:
            return f'"{name}"' if name in cols else fallback
        ts_expr = f"COALESCE({col('ts')}, CAST(strftime('%s',{col('created_at')}) AS INTEGER), CAST(strftime('%s','now') AS INTEGER))"
        kind_expr = f"COALESCE(NULLIF({col('kind')},''),NULLIF({col('event_type')},''),NULLIF({col('source')},''),'legacy')"
        subject_expr = f"COALESCE(NULLIF({col('subject')},''),NULLIF({col('container_name')},''),'host')"
        detail_expr = f"COALESCE(NULLIF({col('detail')},''),NULLIF({col('message')},''),NULLIF({col('payload')},''),'')"
        severity_expr = f"COALESCE(NULLIF({col('severity')},''),'info')"
        c.execute(f"INSERT INTO events(id,ts,kind,subject,detail,severity) SELECT {col('id','NULL')},{ts_expr},{kind_expr},{subject_expr},{detail_expr},{severity_expr} FROM {legacy}")
        c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('last_migration_backup',?)", (backup or '',))
        c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('last_migration_legacy_table',?)", (legacy,))


def init_db() -> None:
    with conn() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, kind TEXT NOT NULL, subject TEXT, detail TEXT, severity TEXT DEFAULT 'info');
        CREATE TABLE IF NOT EXISTS policies(container_name TEXT PRIMARY KEY,auto_restart INTEGER NOT NULL DEFAULT 1,auto_update INTEGER NOT NULL DEFAULT 0,auto_isolate INTEGER NOT NULL DEFAULT 0,allow_rebuild INTEGER NOT NULL DEFAULT 0,protected INTEGER NOT NULL DEFAULT 0,idle_cpu REAL NOT NULL DEFAULT 3.0,idle_minutes INTEGER NOT NULL DEFAULT 20);
        CREATE TABLE IF NOT EXISTS runtime_samples(container_name TEXT PRIMARY KEY, ts INTEGER NOT NULL,cpu REAL NOT NULL DEFAULT 0, rx INTEGER NOT NULL DEFAULT 0, tx INTEGER NOT NULL DEFAULT 0,idle_since INTEGER);
        CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,container_name TEXT NOT NULL, reason TEXT NOT NULL, inspect_json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS security_events(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,source TEXT NOT NULL, severity TEXT NOT NULL, container_name TEXT,message TEXT NOT NULL, raw_json TEXT);
        CREATE TABLE IF NOT EXISTS decisions(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,container_name TEXT, decision TEXT NOT NULL, reason TEXT NOT NULL,executed INTEGER NOT NULL DEFAULT 0, result TEXT);
        CREATE TABLE IF NOT EXISTS correlation_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,container_name TEXT, score INTEGER NOT NULL, risk TEXT NOT NULL,sources_json TEXT NOT NULL, signals_json TEXT NOT NULL,action TEXT NOT NULL, executed INTEGER NOT NULL DEFAULT 0, result TEXT);
        CREATE TABLE IF NOT EXISTS scans(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,container_name TEXT, image TEXT NOT NULL, status TEXT NOT NULL,critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0, medium INTEGER DEFAULT 0,result_json TEXT);
        CREATE TABLE IF NOT EXISTS scan_findings(id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL,container_name TEXT, image TEXT NOT NULL, target TEXT, vuln_id TEXT,pkg_name TEXT, installed_version TEXT, fixed_version TEXT, severity TEXT, title TEXT,FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS risk_profiles(container_name TEXT PRIMARY KEY, profile TEXT NOT NULL DEFAULT 'user-app', weight REAL NOT NULL DEFAULT 1.0);
        CREATE TABLE IF NOT EXISTS suppressions(id INTEGER PRIMARY KEY AUTOINCREMENT, enabled INTEGER NOT NULL DEFAULT 1,source TEXT NOT NULL, container_name TEXT, rule_contains TEXT, reason TEXT,UNIQUE(source,container_name,rule_contains));
        CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, created_ts INTEGER NOT NULL, updated_ts INTEGER NOT NULL,container_name TEXT, severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',title TEXT NOT NULL, summary TEXT, score INTEGER NOT NULL DEFAULT 0,sources_json TEXT NOT NULL DEFAULT '[]', correlation_id INTEGER, resolution TEXT);
        CREATE TABLE IF NOT EXISTS incident_evidence(id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, ts INTEGER NOT NULL,evidence_type TEXT NOT NULL, label TEXT NOT NULL, payload TEXT NOT NULL,FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS recovery_plans(id INTEGER PRIMARY KEY AUTOINCREMENT, created_ts INTEGER NOT NULL, expires_ts INTEGER NOT NULL,container_name TEXT NOT NULL, incident_id INTEGER, action TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',snapshot_id INTEGER, plan_json TEXT NOT NULL, approved_ts INTEGER, executed_ts INTEGER, result TEXT);
        CREATE TABLE IF NOT EXISTS maintenance(container_name TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, until_ts INTEGER, reason TEXT);
        CREATE TABLE IF NOT EXISTS score_history(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, score INTEGER NOT NULL,status TEXT NOT NULL, overall_risk TEXT NOT NULL, monitoring_confidence INTEGER NOT NULL,critical INTEGER NOT NULL DEFAULT 0, high INTEGER NOT NULL DEFAULT 0,medium INTEGER NOT NULL DEFAULT 0, low INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS notification_history(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, severity TEXT NOT NULL,title TEXT NOT NULL, body TEXT NOT NULL, discord_status TEXT, n8n_status TEXT);
        CREATE TABLE IF NOT EXISTS report_history(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, report_type TEXT NOT NULL,payload TEXT NOT NULL, delivered_discord INTEGER NOT NULL DEFAULT 0, delivered_n8n INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS incident_assessments(id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, ts INTEGER NOT NULL,classification TEXT NOT NULL, confidence INTEGER NOT NULL, summary TEXT NOT NULL, factors_json TEXT NOT NULL,top_rule TEXT, FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS recovery_steps(id INTEGER PRIMARY KEY AUTOINCREMENT, plan_id INTEGER NOT NULL, ts INTEGER NOT NULL,step TEXT NOT NULL, status TEXT NOT NULL, detail TEXT, FOREIGN KEY(plan_id) REFERENCES recovery_plans(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS playbook_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL, created_ts INTEGER NOT NULL, completed_ts INTEGER, status TEXT NOT NULL DEFAULT 'running', plan_json TEXT NOT NULL DEFAULT '{}', result_json TEXT NOT NULL DEFAULT '{}', FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE CASCADE);
        CREATE TABLE IF NOT EXISTS sensor_health_history(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, sensor TEXT NOT NULL, status TEXT NOT NULL, detail TEXT, latency_ms INTEGER);
        CREATE TABLE IF NOT EXISTS config_snapshots(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, container_name TEXT NOT NULL, reason TEXT NOT NULL, image_ref TEXT, image_id TEXT, inspect_json TEXT NOT NULL, compose_text TEXT, compose_source TEXT, env_json TEXT NOT NULL DEFAULT '[]', labels_json TEXT NOT NULL DEFAULT '{}', networks_json TEXT NOT NULL DEFAULT '{}', verified INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS update_plans(id INTEGER PRIMARY KEY AUTOINCREMENT, created_ts INTEGER NOT NULL, container_name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'detected', snapshot_id INTEGER, image_ref TEXT NOT NULL, old_image_id TEXT, candidate_image_id TEXT, scan_json TEXT, result_json TEXT NOT NULL DEFAULT '{}', approved_ts INTEGER, executed_ts INTEGER, rollback_snapshot_id INTEGER);
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, actor TEXT NOT NULL DEFAULT 'kingdom', action TEXT NOT NULL, subject TEXT, outcome TEXT NOT NULL, detail TEXT NOT NULL DEFAULT '{}');
        CREATE TABLE IF NOT EXISTS config_baselines(container_name TEXT PRIMARY KEY, ts INTEGER NOT NULL, fingerprint TEXT NOT NULL, config_json TEXT NOT NULL, actor TEXT NOT NULL DEFAULT 'operator');
        CREATE TABLE IF NOT EXISTS backup_status(container_name TEXT PRIMARY KEY, verified_ts INTEGER NOT NULL, provider TEXT NOT NULL DEFAULT 'manual', detail TEXT NOT NULL DEFAULT '');
        CREATE TABLE IF NOT EXISTS validation_runs(id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL, status TEXT NOT NULL, result_json TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_config_snapshots_container_ts ON config_snapshots(container_name,ts);
        CREATE INDEX IF NOT EXISTS idx_update_plans_container_ts ON update_plans(container_name,created_ts);
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
        CREATE INDEX IF NOT EXISTS idx_validation_ts ON validation_runs(ts);
        CREATE INDEX IF NOT EXISTS idx_incident_assessment_incident_ts ON incident_assessments(incident_id, ts);
        CREATE INDEX IF NOT EXISTS idx_recovery_steps_plan_ts ON recovery_steps(plan_id, ts);
        CREATE INDEX IF NOT EXISTS idx_playbook_runs_incident_ts ON playbook_runs(incident_id, created_ts);
        CREATE INDEX IF NOT EXISTS idx_sensor_health_sensor_ts ON sensor_health_history(sensor, ts);
        CREATE INDEX IF NOT EXISTS idx_security_events_subject_ts ON security_events(container_name, ts);
        CREATE INDEX IF NOT EXISTS idx_correlation_subject_ts ON correlation_runs(container_name, ts);
        CREATE INDEX IF NOT EXISTS idx_score_history_ts ON score_history(ts);
        """)
    _migrate_events_if_needed()
    with conn() as c:
        for name, decl in {'auto_restart':'INTEGER NOT NULL DEFAULT 1','auto_update':'INTEGER NOT NULL DEFAULT 0','auto_isolate':'INTEGER NOT NULL DEFAULT 0','allow_rebuild':'INTEGER NOT NULL DEFAULT 0','protected':'INTEGER NOT NULL DEFAULT 0','idle_cpu':'REAL NOT NULL DEFAULT 3.0','idle_minutes':'INTEGER NOT NULL DEFAULT 20','criticality':"TEXT NOT NULL DEFAULT 'normal'",'update_ring':'INTEGER NOT NULL DEFAULT 2','require_backup':'INTEGER NOT NULL DEFAULT 1'}.items():
            _ensure_column(c, 'policies', name, decl)
        _ensure_column(c, 'suppressions', 'expires_ts', 'INTEGER')
        _ensure_column(c, 'suppressions', 'created_ts', 'INTEGER')
        _ensure_column(c, 'incident_assessments', 'score_snapshot', 'INTEGER')
        _ensure_column(c, 'incident_assessments', 'details_json', "TEXT DEFAULT '{}'")
        c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('schema_version',?)", (str(SCHEMA_VERSION),))


init_db()


def now() -> int:
    return int(time.time())


def event(kind: str, subject: str = "", detail: Any = "", severity: str = "info") -> None:
    if not isinstance(detail, str):
        detail = json.dumps(detail, separators=(",", ":"), default=str)
    with conn() as c:
        c.execute("INSERT INTO events(ts,kind,subject,detail,severity) VALUES(?,?,?,?,?)",
                  (now(), kind, subject, detail[:20000], severity))


def rowdicts(rows):
    return [dict(r) for r in rows]


def require_token(authorization: str | None) -> None:
    if not API_TOKEN:
        raise HTTPException(503, "KM_API_TOKEN is not configured")
    if authorization != f"Bearer {API_TOKEN}":
        raise HTTPException(401, "Invalid Kingdom Manager token")


_docker_client: httpx.AsyncClient | None = None
_container_cache: dict[bool, dict[str, Any]] = {True: {"ts": 0.0, "data": []}, False: {"ts": 0.0, "data": []}}
_container_cache_lock = asyncio.Lock()
_sensor_cache: dict[str, Any] = {"ts": 0.0, "data": None}
_sensor_cache_lock = asyncio.Lock()
_api_snapshot: dict[str, Any] = {"ts": 0.0, "score": None}
_api_snapshot_lock = asyncio.Lock()

def _http_client() -> httpx.AsyncClient:
    global _docker_client
    if _docker_client is None:
        timeout=httpx.Timeout(connect=5.0, read=60.0, write=20.0, pool=5.0)
        limits=httpx.Limits(max_connections=24, max_keepalive_connections=12, keepalive_expiry=30.0)
        _docker_client=httpx.AsyncClient(timeout=timeout, limits=limits)
    return _docker_client

async def docker(method: str, path: str, **kwargs) -> httpx.Response:
    client=_http_client()
    try:
        return await client.request(method, DOCKER + path, **kwargs)
    except (httpx.ConnectTimeout, httpx.PoolTimeout) as first:
        # GETs are safe to retry once. Never blindly replay lifecycle POSTs.
        if method.upper() != "GET":
            raise
        await asyncio.sleep(0.15)
        try:
            return await client.request(method, DOCKER + path, **kwargs)
        except httpx.HTTPError as e:
            raise HTTPException(503, f"Docker control plane temporarily unavailable: {type(e).__name__}") from first
    except httpx.HTTPError as e:
        raise HTTPException(503, f"Docker control plane unavailable: {type(e).__name__}: {e}")

async def docker_json(method: str, path: str, ok=(200,), **kwargs):
    r = await docker(method, path, **kwargs)
    if r.status_code not in ok:
        raise HTTPException(r.status_code, r.text[:2000])
    try:
        return r.json() if r.content else None
    except Exception:
        raise HTTPException(502, "Docker API returned a non-JSON response")


async def inspect_container(name: str) -> dict:
    return await docker_json("GET", f"/containers/{quote(name, safe='')}/json")


async def list_containers(all_: bool = True, fresh: bool = False) -> list[dict]:
    key=bool(all_); t=time.monotonic(); cached=_container_cache[key]
    if not fresh and cached["data"] and t-float(cached["ts"]) < DOCKER_CACHE_TTL_SECONDS:
        return [dict(x) for x in cached["data"]]
    async with _container_cache_lock:
        t=time.monotonic(); cached=_container_cache[key]
        if not fresh and cached["data"] and t-float(cached["ts"]) < DOCKER_CACHE_TTL_SECONDS:
            return [dict(x) for x in cached["data"]]
        try:
            data = await docker_json("GET", f"/containers/json?all={1 if all_ else 0}")
            out = []
            for c in data or []:
                out.append({
                    "id": c.get("Id", "")[:12], "full_id": c.get("Id", ""),
                    "name": (c.get("Names") or [""])[0].lstrip("/"),
                    "image": c.get("Image", ""), "image_id": c.get("ImageID", ""),
                    "state": c.get("State", "unknown"), "status": c.get("Status", ""),
                    "labels": c.get("Labels") or {}, "ports": c.get("Ports") or [],
                })
            _container_cache[key]={"ts":time.monotonic(),"data":out}
            return [dict(x) for x in out]
        except Exception:
            age=time.monotonic()-float(cached.get("ts") or 0)
            if cached.get("data") and age <= DOCKER_CACHE_MAX_STALE_SECONDS:
                return [dict(x) for x in cached["data"]]
            raise

def invalidate_container_cache() -> None:
    for key in (True,False): _container_cache[key]["ts"]=0.0
    _api_snapshot["ts"]=0.0

def invalidate_security_snapshot() -> None:
    _api_snapshot["ts"]=0.0


def default_policy(name: str) -> dict:
    with conn() as c:
        r = c.execute("SELECT * FROM policies WHERE container_name=?", (name,)).fetchone()
        if not r:
            n=(name or '').lower(); core=any(x in n for x in ('kingdom-manager','docker-api','portainer','proxy-manager','falco','clamav','crowdsec','trivy'))
            crit='critical' if core else ('high' if any(x in n for x in ('postgres','mysql','mariadb','redis','vaultwarden')) else 'normal')
            ring=4 if core or crit=='high' else 2
            c.execute("INSERT INTO policies(container_name,idle_cpu,idle_minutes,protected,criticality,update_ring,require_backup) VALUES(?,?,?,?,?,?,?)",
                      (name, IDLE_CPU, IDLE_MINUTES, int(core), crit, ring, 1))
            r = c.execute("SELECT * FROM policies WHERE container_name=?", (name,)).fetchone()
    return dict(r)


async def sample_stats(name: str) -> dict:
    r = await docker("GET", f"/containers/{quote(name, safe='')}/stats?stream=false&one-shot=true")
    if r.status_code != 200:
        return {"cpu": 0.0, "rx": 0, "tx": 0}
    s = r.json()
    cpu_stats, pre = s.get("cpu_stats", {}), s.get("precpu_stats", {})
    total = cpu_stats.get("cpu_usage", {}).get("total_usage", 0) - pre.get("cpu_usage", {}).get("total_usage", 0)
    system = cpu_stats.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
    cpus = cpu_stats.get("online_cpus") or len(cpu_stats.get("cpu_usage", {}).get("percpu_usage") or []) or 1
    cpu = (total / system * cpus * 100.0) if total > 0 and system > 0 else 0.0
    rx = tx = 0
    for n in (s.get("networks") or {}).values():
        rx += int(n.get("rx_bytes", 0)); tx += int(n.get("tx_bytes", 0))
    return {"cpu": round(cpu, 2), "rx": rx, "tx": tx}


def update_idle(name: str, stats: dict, policy: dict) -> tuple[bool, int | None]:
    t = now()
    with conn() as c:
        old = c.execute("SELECT * FROM runtime_samples WHERE container_name=?", (name,)).fetchone()
        network_quiet = True
        if old:
            network_quiet = (stats["rx"] - old["rx"] < 1024 * 256 and stats["tx"] - old["tx"] < 1024 * 256)
        low = stats["cpu"] <= float(policy["idle_cpu"]) and network_quiet
        idle_since = (old["idle_since"] if old and old["idle_since"] else t) if low else None
        c.execute("""INSERT INTO runtime_samples(container_name,ts,cpu,rx,tx,idle_since) VALUES(?,?,?,?,?,?)
          ON CONFLICT(container_name) DO UPDATE SET ts=excluded.ts,cpu=excluded.cpu,rx=excluded.rx,tx=excluded.tx,idle_since=excluded.idle_since""",
                  (name, t, stats["cpu"], stats["rx"], stats["tx"], idle_since))
    idle = bool(idle_since and t - idle_since >= int(policy["idle_minutes"]) * 60)
    return idle, idle_since


async def snapshot(name: str, reason: str) -> int:
    obj = await inspect_container(name)
    with conn() as c:
        cur = c.execute("INSERT INTO snapshots(ts,container_name,reason,inspect_json) VALUES(?,?,?,?)",
                        (now(), name, reason, json.dumps(obj, default=str)))
        sid = cur.lastrowid
    event("snapshot", name, {"id": sid, "reason": reason})
    return sid


async def notify(title: str, body: str, severity: str = "info", force: bool = False) -> dict:
    severity = severity.lower()
    rank = {"info":0,"low":1,"notice":1,"warning":2,"medium":2,"high":3,"critical":4}
    should_send = force or rank.get(severity,0) >= rank.get(NOTIFY_MIN_SEVERITY,3)
    payload = {"title":title,"body":body,"severity":severity,"ts":now(),"version":VERSION}
    discord_status = "not-configured" if not DISCORD_WEBHOOK else ("filtered" if not should_send else "pending")
    n8n_status = "not-configured" if not N8N_WEBHOOK else ("filtered" if not should_send else "pending")
    if should_send:
        async with httpx.AsyncClient(timeout=10) as client:
            if DISCORD_WEBHOOK:
                try:
                    mention = f"<@&{DISCORD_ROLE_ID}> " if DISCORD_ROLE_ID and severity in {"high","critical"} else ""
                    color = 0xED4245 if severity=="critical" else 0xF0A020 if severity in {"high","warning","medium"} else 0x57F287 if severity in {"info","low","notice"} else 0x5865F2
                    embed={"title":f"♛ {title}"[:256],"description":body[:3900],"color":color,"footer":{"text":f"Kingdom Manager v{VERSION}"},"timestamp":datetime.now(TZ).isoformat()}
                    if DASHBOARD_URL: embed["url"]=DASHBOARD_URL
                    r=await client.post(DISCORD_WEBHOOK,json={"content":mention,"embeds":[embed],"allowed_mentions":{"roles":[DISCORD_ROLE_ID] if DISCORD_ROLE_ID else []}}); discord_status=f"http-{r.status_code}"
                except Exception as e:
                    discord_status="error:"+str(e)[:180]; event("notify_error","discord",str(e),"warning")
            if N8N_WEBHOOK:
                try:
                    r=await client.post(N8N_WEBHOOK,json=payload); n8n_status=f"http-{r.status_code}"
                except Exception as e:
                    n8n_status="error:"+str(e)[:180]; event("notify_error","n8n",str(e),"warning")
    with conn() as c:
        c.execute("INSERT INTO notification_history(ts,severity,title,body,discord_status,n8n_status) VALUES(?,?,?,?,?,?)",(now(),severity,title[:500],body[:10000],discord_status,n8n_status))
    return {"discord":discord_status,"n8n":n8n_status,"sent":should_send}


async def ensure_quarantine_network() -> None:
    r = await docker("GET", f"/networks/{quote(QUARANTINE_NETWORK, safe='')}")
    if r.status_code == 200:
        return
    r = await docker("POST", "/networks/create", json={"Name": QUARANTINE_NETWORK, "Internal": True, "CheckDuplicate": True})
    if r.status_code not in (201, 409):
        raise HTTPException(r.status_code, r.text)


async def isolate(name: str) -> dict:
    policy = default_policy(name)
    if policy["protected"]:
        raise HTTPException(409, "Protected container cannot be isolated automatically")
    await snapshot(name, "pre-isolation")
    obj = await inspect_container(name)
    await ensure_quarantine_network()
    original = list((obj.get("NetworkSettings", {}).get("Networks") or {}).keys())
    r = await docker("POST", f"/networks/{quote(QUARANTINE_NETWORK, safe='')}/connect", json={"Container": name})
    if r.status_code not in (200, 201, 403):
        raise HTTPException(r.status_code, r.text)
    disconnected = []
    for net in original:
        if net == QUARANTINE_NETWORK:
            continue
        rr = await docker("POST", f"/networks/{quote(net, safe='')}/disconnect", json={"Container": name, "Force": True})
        if rr.status_code in (200, 201):
            disconnected.append(net)
    event("security", name, {"action": "isolated", "from": disconnected}, "critical")
    await notify("Container isolated", f"{name} was moved to {QUARANTINE_NETWORK}. Original networks: {', '.join(disconnected)}", "critical")
    return {"ok": True, "isolated": name, "disconnected": disconnected}


async def restore_networks_from_snapshot(name: str) -> dict:
    with conn() as c:
        r = c.execute("SELECT * FROM snapshots WHERE container_name=? AND reason='pre-isolation' ORDER BY id DESC LIMIT 1", (name,)).fetchone()
    if not r:
        raise HTTPException(404, "No pre-isolation snapshot")
    obj = json.loads(r["inspect_json"])
    networks = list((obj.get("NetworkSettings", {}).get("Networks") or {}).keys())
    restored = []
    for net in networks:
        rr = await docker("POST", f"/networks/{quote(net, safe='')}/connect", json={"Container": name})
        if rr.status_code in (200, 201, 403):
            restored.append(net)
    await docker("POST", f"/networks/{quote(QUARANTINE_NETWORK, safe='')}/disconnect", json={"Container": name, "Force": True})
    event("recovery", name, {"action": "networks_restored", "networks": restored})
    return {"ok": True, "restored": restored}


async def trivy_exec(cmd: list[str], timeout: int = 900) -> tuple[int, str]:
    """Run Trivy through its isolated exec-only Docker proxy, never the general control proxy."""
    client=_http_client()
    try:
        cr=await client.post(TRIVY_EXEC_DOCKER + f"/containers/{quote(TRIVY_RUNNER, safe='')}/exec", json={
            "AttachStdout": True, "AttachStderr": True, "Cmd": cmd
        })
        if cr.status_code != 201:
            raise HTTPException(cr.status_code, f"Trivy exec create failed: {cr.text[:1000]}")
        exid=cr.json()["Id"]
        r=await client.post(TRIVY_EXEC_DOCKER + f"/exec/{exid}/start", json={"Detach": False, "Tty": False}, timeout=timeout)
        raw=r.content.decode("utf-8",errors="ignore")
        p=raw.find("{")
        if p>=0: raw=raw[p:]
        ir=await client.get(TRIVY_EXEC_DOCKER + f"/exec/{exid}/json")
        exit_code=ir.json().get("ExitCode",1) if ir.status_code==200 else (0 if r.status_code==200 else 1)
        return int(exit_code or 0),raw
    except httpx.HTTPError as e:
        raise HTTPException(503,f"Trivy execution proxy unavailable: {type(e).__name__}: {e}")


async def trivy_scan(name: str) -> dict:
    obj = await inspect_container(name)
    image = obj.get("Config", {}).get("Image") or ""
    if not image:
        raise HTTPException(400, "Container has no image reference")

    # Prefer the local Docker image exposed through the dedicated read-only socket proxy;
    # fall back to the registry for images that are not present locally.
    cmd = [
        "trivy", "image", "--quiet", "--format", "json",
        "--scanners", "vuln", "--image-src", "docker,remote",
        "--timeout", "10m", image,
    ]
    exit_code, raw = await trivy_exec(cmd, timeout=720)
    status = "ok" if exit_code == 0 else "error"
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    result: Any = {"raw": raw[-20000:]}
    findings: list[dict] = []
    try:
        result = json.loads(raw)
        for section in result.get("Results") or []:
            target = str(section.get("Target") or "")
            for v in section.get("Vulnerabilities") or []:
                sev = str(v.get("Severity") or "UNKNOWN").lower()
                if sev in counts:
                    counts[sev] += 1
                findings.append({
                    "target": target,
                    "vuln_id": str(v.get("VulnerabilityID") or ""),
                    "pkg_name": str(v.get("PkgName") or ""),
                    "installed_version": str(v.get("InstalledVersion") or ""),
                    "fixed_version": str(v.get("FixedVersion") or ""),
                    "severity": sev,
                    "title": str(v.get("Title") or v.get("Description") or "")[:1000],
                })
    except Exception as e:
        status = "error"
        result = {"error": str(e), "raw": raw[-20000:]}

    with conn() as c:
        cur = c.execute(
            "INSERT INTO scans(ts,container_name,image,status,critical,high,medium,result_json) VALUES(?,?,?,?,?,?,?,?)",
            (now(), name, image, status, counts["critical"], counts["high"], counts["medium"], json.dumps(result, default=str)[:1000000])
        )
        scan_id = cur.lastrowid
        if status == "ok":
            c.executemany(
                "INSERT INTO scan_findings(scan_id,container_name,image,target,vuln_id,pkg_name,installed_version,fixed_version,severity,title) VALUES(?,?,?,?,?,?,?,?,?,?)",
                [(scan_id, name, image, f["target"], f["vuln_id"], f["pkg_name"], f["installed_version"], f["fixed_version"], f["severity"], f["title"]) for f in findings]
            )

    sev = "warning" if status != "ok" else ("critical" if counts["critical"] else ("high" if counts["high"] else "info"))
    invalidate_security_snapshot()
    event("trivy", name, {"image": image, **counts, "status": status, "scan_id": scan_id}, sev)

    decision = None
    if status == "ok" and (counts["critical"] or counts["high"]):
        # Feed the scan into the same correlation engine used by runtime detections.
        # Trivy is contextual exposure evidence and can never isolate by itself.
        trigger_sev = "critical" if counts["critical"] else "high"
        decision = await correlate_security(
            name, "trivy", trigger_sev,
            f"{counts['critical']} critical and {counts['high']} high vulnerabilities in {image}"
        )
        if counts["critical"]:
            await notify("Critical image vulnerabilities", f"{name} ({image}) has {counts['critical']} critical and {counts['high']} high findings. No isolation occurs from Trivy alone.", "critical")

    top = [f for f in findings if f["severity"] in {"critical", "high"}][:20]
    error_detail = None
    if status != "ok":
        if isinstance(result, dict):
            error_detail = str(result.get("error") or result.get("raw") or "Trivy scan failed")[-1200:]
        else:
            error_detail = "Trivy scan failed"
    return {"scan_id": scan_id, "container": name, "image": image, "status": status, **counts,
            "total": len(findings), "top_findings": top, "decision": decision, "error": error_detail}


async def pull_image(image: str) -> dict:
    # Works for public registries. Private registry auth can be added later without storing credentials in the DB.
    before = None
    r0 = await docker("GET", f"/images/{quote(image, safe='')}/json")
    if r0.status_code == 200:
        before = r0.json().get("Id")
    r = await docker("POST", f"/images/create?fromImage={quote(image, safe='')}")
    if r.status_code not in (200, 201):
        raise HTTPException(r.status_code, r.text[-2000:])
    r1 = await docker("GET", f"/images/{quote(image, safe='')}/json")
    after = r1.json().get("Id") if r1.status_code == 200 else None
    return {"image": image, "before": before, "after": after, "update_available": bool(before and after and before != after)}


def inferred_profile(name: str) -> tuple[str, float]:
    n=(name or '').lower()
    if any(x in n for x in ('cowrie','opencanary','honeypot')): return ('honeypot', 0.4)
    if any(x in n for x in ('kingdom-manager','proxy-manager','portainer','vaultwarden')): return ('critical-infrastructure', 1.5)
    if any(x in n for x in ('postgres','mysql','mariadb','redis','database','_db','-db')): return ('database', 1.3)
    if any(x in n for x in ('falco','clamav','crowdsec','trivy')): return ('security', 1.2)
    return ('user-app', 1.0)


def risk_profile(name: str) -> dict:
    with conn() as c:
        r=c.execute('SELECT profile,weight FROM risk_profiles WHERE container_name=?',(name,)).fetchone()
        if r: return dict(r)
    profile,weight=inferred_profile(name)
    return {'profile':profile,'weight':weight}


def falco_rule_from_message(message: str) -> str:
    m=(message or '').lower()
    if 'drop and execute new binary' in m: return 'Drop and execute new binary in container'
    if 'sensitive file opened' in m or '/etc/shadow' in m: return 'Read sensitive file untrusted'
    if 'executing binary not part of base image' in m: return 'Executing binary not part of base image'
    if 'redirect stdout/stdin' in m: return 'Redirect STDOUT/STDIN to Network Connection in Container'
    return ''


def falco_baseline_metrics(name: str | None, rule: str = '', days: int = BASELINE_DAYS) -> dict:
    """Describe how established a Falco behavior is without auto-trusting it.

    Baselines are advisory. They can attenuate Falco-only scoring when a recent
    Trivy scan is clean, but they never suppress events or authorize recovery.
    """
    if not name:
        return {'status':'unknown','confidence':0,'count':0,'span_hours':0.0,'days_seen':0,'score_adjustment':0}
    cutoff=now()-max(1,days)*86400
    with conn() as c:
        rows=c.execute("SELECT ts,message,raw_json,severity FROM security_events WHERE source='falco' AND container_name=? AND ts>? ORDER BY ts",(name,cutoff)).fetchall()
    matches=[]
    for r in rows:
        raw=_safe_json(r['raw_json'],{}) or {}
        rr=str(raw.get('rule') or falco_rule_from_message(r['message']) or 'Other Falco rule')
        if rule and rr != rule:
            continue
        matches.append((int(r['ts']),rr,str(r['severity'] or 'info').lower()))
    if not matches:
        return {'status':'novel','confidence':20,'count':0,'span_hours':0.0,'days_seen':0,'score_adjustment':0,'rule':rule}
    first,last=matches[0][0],matches[-1][0]
    count=len(matches); span=max(0,last-first); span_hours=round(span/3600,1); days_seen=max(1,int(span//86400)+1)
    # Stable requires both repetition and time. A burst of thousands of events in
    # ten minutes is noisy, not a trustworthy baseline.
    if count>=BASELINE_STABLE_MIN_EVENTS and span>=BASELINE_STABLE_MIN_HOURS*3600:
        status='stable'
    elif count>=20 and span>=2*3600:
        status='learning'
    else:
        status='novel'
    confidence=min(95,30 + min(35,int(count/50)*3) + min(30,int(span_hours/6)*4))
    # Advisory score adjustment only; applied only to Falco-only + clean-Trivy cases.
    adjustment = -BASELINE_STABLE_ATTENUATION if status=='stable' else (-BASELINE_LEARNING_ATTENUATION if status=='learning' else 0)
    return {'status':status,'confidence':confidence,'count':count,'span_hours':span_hours,'days_seen':days_seen,'score_adjustment':adjustment,'rule':rule,'first_ts':first,'last_ts':last}


def latest_scan_context(name: str | None, successful_only: bool = False) -> dict | None:
    if not name:
        return None
    q="SELECT id,ts,image,status,critical,high,medium,result_json FROM scans WHERE container_name=?"
    params=[name]
    if successful_only:
        q += " AND status='ok'"
    q += " ORDER BY id DESC LIMIT 1"
    with conn() as c:
        r=c.execute(q,params).fetchone()
    return dict(r) if r else None


def normalize_rule(value: str) -> str:
    """Normalize rule text for resilient exact-scope matching across Falco formats."""
    return ' '.join(''.join(ch.lower() if ch.isalnum() else ' ' for ch in str(value or '')).split())


def resolve_signal_rule(source: str, name: str | None, signal: dict) -> str:
    """Resolve the concrete engine rule for a stored signal, including legacy rows.

    Older correlation rows stored the Falco message but not raw_json/rule. We first
    derive from the message, then look up the nearest source event by timestamp so
    approvals created later can still match those historical correlation rows.
    """
    source=(source or '').lower()
    msg=str(signal.get('message') or '')
    if source!='falco':
        return ''
    derived=falco_rule_from_message(msg)
    if derived:
        return derived
    ts=int(signal.get('ts') or 0)
    if not name:
        return ''
    with conn() as c:
        if ts:
            row=c.execute("SELECT message,raw_json FROM security_events WHERE source='falco' AND container_name=? AND ts BETWEEN ? AND ? ORDER BY abs(ts-?) ASC,id DESC LIMIT 1",(name,ts-10,ts+10,ts)).fetchone()
        else:
            row=c.execute("SELECT message,raw_json FROM security_events WHERE source='falco' AND container_name=? ORDER BY id DESC LIMIT 1",(name,)).fetchone()
    if not row:
        return ''
    raw=_safe_json(row['raw_json'],{}) or {}
    return str(raw.get('rule') or falco_rule_from_message(row['message']) or '')


def active_suppression(source: str, name: str | None, message: str = '', rule: str = '') -> dict | None:
    source=(source or '').lower(); name=name or ''
    if source=='falco' and not rule:
        rule=falco_rule_from_message(message)
    # Match normalized rule text first, then fall back to normalized message text.
    # This tolerates Falco punctuation/case changes without broadening the scope to
    # another container or another rule.
    hay_rule=normalize_rule(rule)
    hay_message=normalize_rule(message)
    with conn() as c:
        rows=c.execute("SELECT id,source,container_name,rule_contains,reason,expires_ts,created_ts FROM suppressions WHERE enabled=1 AND source=? AND (expires_ts IS NULL OR expires_ts>?) ORDER BY id DESC",(source,now())).fetchall()
    for r in rows:
        if (r['container_name'] or '') != name:
            continue
        needle=normalize_rule(r['rule_contains'])
        if needle:
            if hay_rule:
                if needle != hay_rule and needle not in hay_rule and hay_rule not in needle:
                    continue
            elif needle not in hay_message:
                continue
        d=dict(r); d['active']=True
        return d
    return None


def is_suppressed(source: str, name: str | None, message: str) -> tuple[bool,str]:
    r=active_suppression(source,name,message)
    return (bool(r), str((r or {}).get('reason') or 'known-good suppression') if r else '')


def signal_weight(signal: dict) -> int:
    if signal.get('weight') is not None:
        try: return int(signal.get('weight') or 0)
        except Exception: pass
    sev=str(signal.get('severity') or 'info').lower()
    source=str(signal.get('source') or '').lower()
    return {'critical':45,'high':25,'warning':20,'medium':12,'info':5,'notice':5,'low':3}.get(sev,5) + {'clamav':20,'crowdsec':10}.get(source,0)


def suppression_aware_correlation(name: str, cr: dict) -> dict:
    """Re-evaluate a stored correlation run against suppressions that are active *now*.

    This prevents stale, pre-approval correlation rows from continuing to penalize
    a container after an operator explicitly marks an exact container+rule as expected.
    """
    original=max(0,min(100,int(cr.get('score') or 0)))
    try: signals=_safe_json(cr.get('signals_json'),'[]') or []
    except Exception: signals=[]
    if not isinstance(signals,list): signals=[]
    if not signals:
        return {'original':original,'effective':original,'suppressed':[],'remaining_sources':_safe_json(cr.get('sources_json'),'[]') or []}
    effective=0; suppressed=[]; remaining=[]
    for sig in signals:
        if not isinstance(sig,dict):
            continue
        src=str(sig.get('source') or '').lower(); msg=str(sig.get('message') or '')
        resolved_rule=resolve_signal_rule(src,name,sig)
        sup=active_suppression(src,name,msg,rule=resolved_rule)
        if sup:
            suppressed.append({'source':src,'rule':sup.get('rule_contains'),'reason':sup.get('reason'),'expires_ts':sup.get('expires_ts')})
            continue
        effective += signal_weight(sig); remaining.append(src)
    if suppressed:
        if effective <= 0:
            effective=min(original,max(0,KNOWN_GOOD_RESIDUAL_RISK))
        effective=max(0,min(original,effective))
        # A known-good approval may attenuate but never remove more than the configured cap.
        effective=max(effective,max(0,original-KNOWN_GOOD_MAX_ATTENUATION))
    else:
        effective=original
    return {'original':original,'effective':effective,'suppressed':suppressed,'remaining_sources':sorted(set(remaining))}


def current_security_context(name: str) -> dict:
    """Canonical live-risk evaluation for one container.

    Rebuild the strongest current evidence directly from security_events and the
    latest successful Trivy scan, applying active exact-scope suppressions at read
    time. This is the source of truth for dashboard scoring so a stale historical
    correlation row cannot keep charging risk after operator approval.
    """
    t=now(); cutoff=t-DECISION_WINDOW_SECONDS
    sev_weight={"critical":45,"high":25,"warning":20,"medium":12,"info":5,"notice":5,"low":3}
    source_bonus={"clamav":20,"falco":0,"crowdsec":10,"trivy":0}
    raw_strongest={}; effective_strongest={}; suppressed=[]
    with conn() as c:
        rows=c.execute(
            "SELECT source,severity,message,raw_json,ts FROM security_events WHERE container_name=? AND ts>? ORDER BY ts DESC",
            (name,cutoff)
        ).fetchall()
        scan=c.execute(
            "SELECT ts,critical,high,medium,image FROM scans WHERE container_name=? AND status='ok' AND ts>? ORDER BY id DESC LIMIT 1",
            (name,t-TRIVY_CONTEXT_SECONDS)
        ).fetchone()
    for r in rows:
        src=str(r['source'] or '').lower(); sev=str(r['severity'] or 'info').lower()
        weight=sev_weight.get(sev,5)+source_bonus.get(src,0)
        raw=_safe_json(r['raw_json'],{}) or {}
        rule=str(raw.get('rule') or (falco_rule_from_message(r['message']) if src=='falco' else '') or '')
        sig={'source':src,'severity':sev,'message':str(r['message'] or ''),'rule':rule,'ts':int(r['ts'] or 0),'weight':weight}
        old=raw_strongest.get(src)
        if old is None or weight>old['weight']:
            raw_strongest[src]=sig
        sup=active_suppression(src,name,sig['message'],rule=rule)
        if sup:
            suppressed.append({'source':src,'rule':str(sup.get('rule_contains') or rule),'reason':sup.get('reason'),'expires_ts':sup.get('expires_ts'),'weight':weight})
            continue
        old=effective_strongest.get(src)
        if old is None or weight>old['weight']:
            effective_strongest[src]=sig
    if scan and (int(scan['critical'] or 0) or int(scan['high'] or 0)):
        w=25 if int(scan['critical'] or 0) else 12
        tri={'source':'trivy','severity':'critical' if int(scan['critical'] or 0) else 'high','message':f"{scan['critical']} critical / {scan['high']} high CVEs in {scan['image']}",'rule':'','ts':int(scan['ts'] or 0),'weight':w}
        raw_strongest['trivy']=tri; effective_strongest['trivy']=tri
    original=min(100,sum(int(x['weight']) for x in raw_strongest.values()))
    effective=min(100,sum(int(x['weight']) for x in effective_strongest.values()))
    if suppressed:
        # Residual risk exists only when the approved behavior is the only remaining
        # live evidence. Independent corroboration keeps its full weight.
        if effective<=0:
            effective=min(original,max(0,KNOWN_GOOD_RESIDUAL_RISK))
        effective=max(effective,max(0,original-KNOWN_GOOD_MAX_ATTENUATION))
    risk='low' if effective<30 else ('medium' if effective<60 else ('high' if effective<90 else 'critical'))
    return {
        'original':original,'effective':effective,'risk':risk,
        'raw_sources':sorted(raw_strongest.keys()),
        'remaining_sources':sorted(effective_strongest.keys()),
        'suppressed':suppressed,'signals':list(effective_strongest.values()),
        'window_seconds':DECISION_WINDOW_SECONDS,
    }


async def correlate_security(name: str | None, trigger_source: str, trigger_severity: str, trigger_message: str) -> dict:
    """Correlate independent security engines before allowing an automated response.

    Repeated events from one engine do not multiply risk. For each source we keep
    only the strongest recent signal. Trivy is contextual vulnerability evidence,
    not proof of compromise, so it can raise risk/recommend an update but cannot
    by itself cause isolation.
    """
    subject = name or "host"
    t = now()
    suppressed, suppression_reason = is_suppressed(trigger_source, name, trigger_message)
    if suppressed:
        with conn() as c:
            c.execute("INSERT INTO correlation_runs(ts,container_name,score,risk,sources_json,signals_json,action,executed,result) VALUES(?,?,?,?,?,?,?,?,?)",
                      (t,name,0,"low",json.dumps([trigger_source]),json.dumps([{"source":trigger_source,"suppressed":True,"reason":suppression_reason}]),"suppressed",0,suppression_reason))
        return {"risk":"low","score":0,"action":"suppressed","executed":False,"reason":suppression_reason,"sources":[trigger_source]}
    severity_weight = {"critical": 45, "high": 25, "warning": 20, "medium": 12, "info": 5, "notice": 5, "low": 3}
    source_bonus = {"clamav": 20, "falco": 0, "crowdsec": 10, "trivy": 0}
    strongest: dict[str, dict] = {}

    with conn() as c:
        rows = c.execute(
            "SELECT source,severity,message,ts FROM security_events WHERE coalesce(container_name,'host')=? AND ts>? ORDER BY ts DESC",
            (subject, t - DECISION_WINDOW_SECONDS)
        ).fetchall()
        for r in rows:
            src = str(r["source"]).lower()
            sev = str(r["severity"]).lower()
            weight = severity_weight.get(sev, 5) + source_bonus.get(src, 0)
            old = strongest.get(src)
            if old is None or weight > old["weight"]:
                strongest[src] = {"source": src, "severity": sev, "message": r["message"], "ts": r["ts"], "weight": weight}

        # Latest Trivy scan contributes exposure context for a container, but never counts as active compromise.
        if name:
            scan = c.execute(
                "SELECT ts,critical,high,medium,image FROM scans WHERE container_name=? AND status='ok' AND ts>? ORDER BY id DESC LIMIT 1",
                (name, t - TRIVY_CONTEXT_SECONDS)
            ).fetchone()
            if scan and (scan["critical"] or scan["high"]):
                w = 25 if scan["critical"] else 12
                strongest["trivy"] = {
                    "source":"trivy", "severity":"critical" if scan["critical"] else "high",
                    "message":f"{scan['critical']} critical / {scan['high']} high CVEs in {scan['image']}",
                    "ts":scan["ts"], "weight":w
                }

    active_sources = {k:v for k,v in strongest.items() if k != "trivy"}
    score = sum(v["weight"] for v in strongest.values())
    source_count = len(active_sources)
    malware = any(k == "clamav" and (v["severity"] in {"critical","high"} or "infect" in v["message"].lower() or "malware" in v["message"].lower()) for k,v in strongest.items())
    falco_critical = strongest.get("falco", {}).get("severity") == "critical"
    crowdsec_signal = "crowdsec" in active_sources
    vulnerable = "trivy" in strongest

    if score >= 90 and source_count >= 2:
        risk, action = "critical", "recommend_isolation"
    elif malware and source_count >= 2:
        risk, action = "critical", "recommend_isolation"
    elif score >= 60 or (falco_critical and vulnerable) or (falco_critical and crowdsec_signal):
        risk, action = "high", "investigate"
    elif malware:
        risk, action = "high", "quarantine_evidence"
    elif vulnerable and source_count == 0:
        risk, action = "medium", "recommend_update"
    elif score >= 30:
        risk, action = "medium", "investigate"
    else:
        risk, action = "low", "record"

    execute = False
    result: Any = None
    policy = default_policy(name) if name else None
    if action == "recommend_isolation" and name and policy and policy["auto_isolate"] and not policy["protected"]:
        action = "isolate"
        execute = True

    signals = list(strongest.values())
    sources = sorted(strongest.keys())
    reason = f"correlated risk={risk} score={score} sources={','.join(sources) or trigger_source}: {trigger_message}"

    # Debounce identical decisions for the same subject. Events are still retained.
    with conn() as c:
        previous = c.execute(
            "SELECT id,ts,action,score,risk FROM correlation_runs WHERE coalesce(container_name,'host')=? ORDER BY id DESC LIMIT 1",
            (subject,)
        ).fetchone()
        if previous and previous["action"] == action and t - int(previous["ts"]) < DECISION_DEBOUNCE_SECONDS:
            return {"id": previous["id"], "decision": action, "risk": risk, "score": score, "sources": sources, "executed": False, "debounced": True}

        cur = c.execute(
            "INSERT INTO correlation_runs(ts,container_name,score,risk,sources_json,signals_json,action,executed) VALUES(?,?,?,?,?,?,?,?)",
            (t, name, score, risk, json.dumps(sources), json.dumps(signals, default=str), action, int(execute))
        )
        correlation_id = cur.lastrowid
        dcur = c.execute("INSERT INTO decisions(ts,container_name,decision,reason,executed) VALUES(?,?,?,?,?)",
                         (t, name, action, reason, int(execute)))
        decision_id = dcur.lastrowid

    if execute and name:
        try:
            result = await isolate(name)
        except Exception as e:
            result = {"error": str(e)}
            with conn() as c:
                c.execute("UPDATE correlation_runs SET result=? WHERE id=?", (json.dumps(result), correlation_id))
                c.execute("UPDATE decisions SET result=? WHERE id=?", (json.dumps(result), decision_id))
    if risk in {"high", "critical"}:
        await notify(
            f"Kingdom {risk.upper()} risk",
            f"{subject} — score {score} from {', '.join(sources)}\nDecision: {action}\nTrigger: {trigger_message}",
            risk
        )
    return {"id": decision_id, "correlation_id": correlation_id, "decision": action, "risk": risk, "score": score, "sources": sources, "signals": signals, "executed": execute, "result": result}


def global_maintenance_active() -> bool:
    with conn() as c:
        r=c.execute("SELECT value FROM settings WHERE key='global_maintenance'").fetchone()
    if not r: return False
    d=_safe_json(r[0],{}) or {}
    if not d.get('enabled'): return False
    until=d.get('until_ts')
    if until and int(until)<now():
        with conn() as c: c.execute("DELETE FROM settings WHERE key='global_maintenance'")
        return False
    return True

def maintenance_active(name: str | None) -> bool:
    if not name: return False
    with conn() as c:
        r=c.execute("SELECT enabled,until_ts FROM maintenance WHERE container_name=?",(name,)).fetchone()
    return bool(r and r["enabled"] and (not r["until_ts"] or int(r["until_ts"])>now()))

def upsert_incident(name: str | None, decision: dict, trigger_source: str, message: str) -> int | None:
    risk=str(decision.get("risk","low")); score=int(decision.get("score",0) or 0)
    if risk not in {"medium","high","critical"}: return None
    subject=name or "host"; t=now(); sources=decision.get("sources") or [trigger_source]
    with conn() as c:
        r=c.execute("SELECT id,sources_json FROM incidents WHERE coalesce(container_name,'host')=? AND status IN ('open','investigating','isolated') ORDER BY id DESC LIMIT 1",(subject,)).fetchone()
        if r:
            merged=sorted(set(json.loads(r["sources_json"] or '[]')+list(sources)))
            c.execute("UPDATE incidents SET updated_ts=?,severity=?,score=?,sources_json=?,summary=? WHERE id=?",(t,risk,score,json.dumps(merged),message[:1000],r["id"]))
            iid=int(r["id"])
        else:
            cur=c.execute("INSERT INTO incidents(created_ts,updated_ts,container_name,severity,status,title,summary,score,sources_json,correlation_id) VALUES(?,?,?,?,?,?,?,?,?,?)",(t,t,name,risk,'open',f'{risk.upper()} security incident — {subject}',message[:1000],score,json.dumps(sources),decision.get('correlation_id')))
            iid=int(cur.lastrowid)
        c.execute("INSERT INTO incident_evidence(incident_id,ts,evidence_type,label,payload) VALUES(?,?,?,?,?)",(iid,t,'signal',trigger_source,json.dumps({'message':message,'decision':decision},default=str)[:100000]))
    return iid

async def decision_for_security(source: str, severity: str, name: str | None, message: str) -> dict:
    if maintenance_active(name):
        event('maintenance_signal',name or 'host',{'source':source,'message':message},severity)
        return {'risk':'low','score':0,'action':'maintenance-record','executed':False,'sources':[source],'maintenance':True}
    d=await correlate_security(name, source.lower(), severity.lower(), message)
    iid=upsert_incident(name,d,source,message)
    if iid:
        d['incident_id']=iid
        if AUTO_SAFE_PLAYBOOKS and PLAYBOOKS_ENABLED and not global_maintenance_active():
            with conn() as c:
                recent=c.execute('SELECT id FROM playbook_runs WHERE incident_id=? AND created_ts>? ORDER BY id DESC LIMIT 1',(iid,now()-600)).fetchone()
            if not recent:
                asyncio.create_task(run_safe_playbook(iid,f'Bearer {API_TOKEN}'))
    return d


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/health")
async def health():
    r = await docker("GET", "/_ping")
    return {"ok": r.status_code == 200, "version": VERSION, "docker": r.text.strip() if r.status_code == 200 else "down"}


@app.get("/ready")
async def ready():
    checks={}
    try:
        r=await docker("GET","/_ping"); checks['docker']=r.status_code==200
    except Exception: checks['docker']=False
    try:
        with conn() as c: checks['database']=c.execute("PRAGMA quick_check").fetchone()[0]=='ok'; checks['schema']=int(c.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone()[0])==SCHEMA_VERSION
    except Exception: checks['database']=False; checks['schema']=False
    ok=all(checks.values()); return {'ok':ok,'version':VERSION,'checks':checks}

POLICY_PRESETS={
 'test':{'criticality':'normal','update_ring':1,'auto_update':0,'auto_isolate':0,'allow_rebuild':1,'protected':0,'require_backup':0},
 'user-app':{'criticality':'normal','update_ring':2,'auto_update':0,'auto_isolate':0,'allow_rebuild':1,'protected':0,'require_backup':1},
 'important':{'criticality':'high','update_ring':3,'auto_update':0,'auto_isolate':0,'allow_rebuild':1,'protected':0,'require_backup':1},
 'database':{'criticality':'critical','update_ring':4,'auto_update':0,'auto_isolate':0,'allow_rebuild':0,'protected':1,'require_backup':1},
 'security':{'criticality':'critical','update_ring':4,'auto_update':0,'auto_isolate':0,'allow_rebuild':0,'protected':1,'require_backup':1},
 'honeypot':{'criticality':'normal','update_ring':2,'auto_update':0,'auto_isolate':0,'allow_rebuild':1,'protected':0,'require_backup':1},
}

@app.get('/api/policies/presets')
async def policy_presets(authorization: str|None=Header(default=None)):
    require_token(authorization); return POLICY_PRESETS

@app.post('/api/policies/{name}/preset/{preset}')
async def apply_policy_preset(name: str,preset: str,authorization: str|None=Header(default=None)):
    require_token(authorization)
    if preset not in POLICY_PRESETS: raise HTTPException(404,'Unknown policy preset')
    d=POLICY_PRESETS[preset]; current=default_policy(name); current.update(d)
    with conn() as c:
        c.execute("UPDATE policies SET auto_update=?,auto_isolate=?,allow_rebuild=?,protected=?,criticality=?,update_ring=?,require_backup=? WHERE container_name=?",(int(current['auto_update']),int(current['auto_isolate']),int(current['allow_rebuild']),int(current['protected']),current['criticality'],int(current['update_ring']),int(current['require_backup']),name))
    audit('policy-preset',name,'success',{'preset':preset}) if 'audit' in globals() else event('policy',name,{'preset':preset})
    return default_policy(name)

@app.get("/api/overview")
async def overview(authorization: str | None = Header(default=None)):
    require_token(authorization)
    cs = await list_containers()
    running = sum(c["state"] == "running" for c in cs)
    with conn() as c:
        sec24 = c.execute("SELECT count(*) FROM security_events WHERE ts>?", (now()-86400,)).fetchone()[0]
        dec24 = c.execute("SELECT count(*) FROM decisions WHERE ts>?", (now()-86400,)).fetchone()[0]
        scans = c.execute("SELECT count(*) FROM scans").fetchone()[0]
    return {"containers": len(cs), "running": running, "stopped": len(cs)-running,
            "security_24h": sec24, "decisions_24h": dec24, "scans": scans, "version": VERSION}


@app.get("/api/auth/verify")
async def auth_verify(authorization: str | None = Header(default=None)):
    require_token(authorization)
    return {"ok": True, "version": VERSION, "ts": now()}


@app.get("/api/dashboard/bootstrap")
async def dashboard_bootstrap(authorization: str | None = Header(default=None)):
    """Fast warm-start payload. Never waits on Docker or security engines."""
    require_token(authorization)
    score = _api_snapshot.get("score")
    saved_ts = now() if score else 0
    source = "memory" if score else "none"
    if not score:
        try:
            data=json.loads(DASHBOARD_SNAPSHOT_PATH.read_text())
            score=data.get("score")
            saved_ts=int(data.get("saved_ts") or 0)
            source="disk" if score else "none"
        except Exception:
            score=None
    return {"ok":True,"version":VERSION,"source":source,"saved_ts":saved_ts,"score":score}

@app.get("/api/system/performance")
async def system_performance(authorization: str | None = Header(default=None)):
    require_token(authorization)
    return {
        "container_cache": {str(k).lower(): {"age_seconds": (round(max(0.0,time.monotonic()-float(v.get('ts') or 0)),2) if v.get('data') else None), "items": len(v.get('data') or [])} for k,v in _container_cache.items()},
        "sensor_cache_age_seconds": round(max(0.0,time.monotonic()-float(_sensor_cache.get('ts') or 0)),2) if _sensor_cache.get('data') else None,
        "docker_cache_ttl_seconds": DOCKER_CACHE_TTL_SECONDS,
        "sensor_cache_ttl_seconds": SENSOR_CACHE_TTL_SECONDS,
    }

@app.get("/api/containers")
async def api_containers(authorization: str | None = Header(default=None)):
    require_token(authorization)
    cs = await list_containers()
    for c in cs:
        c["policy"] = default_policy(c["name"])
        with conn() as db:
            s = db.execute("SELECT cpu,idle_since,ts FROM runtime_samples WHERE container_name=?", (c["name"],)).fetchone()
        c["runtime"] = dict(s) if s else None
    return cs


@app.post("/api/containers/{name}/action/{action}")
async def container_action(name: str, action: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    if action not in {"start", "stop", "restart", "pause", "unpause"}:
        raise HTTPException(400, "Unsupported action")
    p = default_policy(name)
    if p["protected"] and action in {"stop", "pause"}:
        raise HTTPException(409, "Container is protected by Kingdom policy")
    if action in {"stop", "restart", "pause"}:
        await snapshot(name, f"pre-{action}")
    r = await docker("POST", f"/containers/{quote(name, safe='')}/{action}")
    if r.status_code not in (204, 304):
        raise HTTPException(r.status_code, r.text[:2000])
    invalidate_container_cache()
    event("container", name, action)
    return {"ok": True, "container": name, "action": action}


@app.post("/api/containers/{name}/sample")
async def manual_sample(name: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    p = default_policy(name)
    s = await sample_stats(name)
    idle, idle_since = update_idle(name, s, p)
    return {**s, "idle": idle, "idle_since": idle_since}


@app.put("/api/policies/{name}")
async def set_policy(name: str, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization)
    data = await request.json()
    allowed = {"auto_restart", "auto_update", "auto_isolate", "allow_rebuild", "protected", "idle_cpu", "idle_minutes", "criticality", "update_ring", "require_backup"}
    current = default_policy(name)
    for k, v in data.items():
        if k in allowed:
            current[k] = v
    with conn() as c:
        c.execute("""UPDATE policies SET auto_restart=?,auto_update=?,auto_isolate=?,allow_rebuild=?,protected=?,idle_cpu=?,idle_minutes=? WHERE container_name=?""",
                  (int(bool(current["auto_restart"])), int(bool(current["auto_update"])), int(bool(current["auto_isolate"])),
                   int(bool(current["allow_rebuild"])), int(bool(current["protected"])), float(current["idle_cpu"]), int(current["idle_minutes"]), name))
        c.execute("UPDATE policies SET criticality=?,update_ring=?,require_backup=? WHERE container_name=?",(str(current.get("criticality","normal")),max(1,min(4,int(current.get("update_ring",2)))),int(bool(current.get("require_backup",1))),name))
    event("policy", name, data)
    return default_policy(name)


@app.post("/api/security/event")
async def security_event(request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization)
    data = await request.json()
    source = str(data.get("source", "unknown"))
    severity = str(data.get("severity", "info")).lower()
    name = data.get("container") or data.get("container_name")
    message = str(data.get("message", "security event"))
    with conn() as c:
        c.execute("INSERT INTO security_events(ts,source,severity,container_name,message,raw_json) VALUES(?,?,?,?,?,?)",
                  (now(), source, severity, name, message, json.dumps(data, default=str)[:100000]))
    event("security_event", name or "host", {"source": source, "message": message}, severity)
    decision = await decision_for_security(source, severity, name, message)
    return {"ok": True, "decision": decision}


@app.post("/api/security/falco")
async def falco_webhook(request: Request, token: str = ""):
    # Falco posts here directly over the private security network.
    # A shared token prevents the same route being abused through the web proxy.
    if FALCO_WEBHOOK_SECRET and token != FALCO_WEBHOOK_SECRET:
        raise HTTPException(401, "Invalid Falco webhook token")
    data = await request.json()
    severity = str(data.get("priority", "warning")).lower()
    if severity in {"emergency", "alert", "critical"}: severity = "critical"
    elif severity in {"error", "warning"}: severity = "high"
    else: severity = "info"
    output_fields = data.get("output_fields") or {}
    name = output_fields.get("container.name") or output_fields.get("container_name")
    msg = str(data.get("output", data.get("rule", "Falco event")))
    with conn() as c:
        c.execute("INSERT INTO security_events(ts,source,severity,container_name,message,raw_json) VALUES(?,?,?,?,?,?)",
                  (now(), "falco", severity, name, msg, json.dumps(data, default=str)[:100000]))
    invalidate_security_snapshot()
    return await decision_for_security("falco", severity, name, msg)


@app.post("/api/containers/{name}/isolate")
async def api_isolate(name: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    return await isolate(name)


@app.post("/api/containers/{name}/restore-networks")
async def api_restore_networks(name: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    return await restore_networks_from_snapshot(name)


@app.post("/api/containers/{name}/trivy")
async def api_trivy(name: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    return await trivy_scan(name)


@app.post("/api/containers/{name}/check-update")
async def check_update(name: str, authorization: str | None = Header(default=None)):
    require_token(authorization)
    obj = await inspect_container(name)
    image = obj.get("Config", {}).get("Image")
    result = await pull_image(image)
    event("update_check", name, result, "info")
    return result



async def _probe_clamav() -> dict:
    """Protocol-level clamd liveness check. TCP-open alone is not considered healthy."""
    started=time.monotonic()
    out={"configured":bool(CLAMAV_HOST),"endpoint":f"{CLAMAV_HOST}:{CLAMAV_PORT}"}
    if not CLAMAV_HOST:
        return {**out,"status":"not configured","detail":"CLAMAV_HOST is empty"}
    writer=None
    try:
        reader,writer=await asyncio.wait_for(asyncio.open_connection(CLAMAV_HOST,CLAMAV_PORT),timeout=3)
        writer.write(b"zPING\0"); await writer.drain()
        resp=await asyncio.wait_for(reader.read(64),timeout=3)
        clean=resp.strip(b"\x00\r\n ")
        out.update({"reachable":True,"response":clean.decode(errors="replace"),"latency_ms":round((time.monotonic()-started)*1000)})
        if clean.upper()==b"PONG":
            out["status"]="ok"; out["detail"]="clamd protocol PING/PONG verified"
        else:
            out["status"]="down"; out["detail"]="Unexpected clamd response: "+repr(resp[:64])
    except Exception as e:
        out.update({"status":"down","detail":f"{type(e).__name__}: {e}","latency_ms":round((time.monotonic()-started)*1000)})
    finally:
        if writer is not None:
            try:
                writer.close(); await writer.wait_closed()
            except Exception: pass
    return out

async def _probe_crowdsec() -> dict:
    started=time.monotonic(); out={"configured":bool(CROWDSEC_URL)}
    if not CROWDSEC_URL: return {**out,"status":"not configured","detail":"CROWDSEC_URL is empty"}
    try:
        async with httpx.AsyncClient(timeout=3,verify=False) as client:
            h={"X-Api-Key":CROWDSEC_API_KEY} if CROWDSEC_API_KEY else {}
            r=await client.get(CROWDSEC_URL.rstrip("/")+"/v1/decisions",headers=h)
        out.update({"http":r.status_code,"latency_ms":round((time.monotonic()-started)*1000)})
        if 200 <= r.status_code < 300:
            out.update({"status":"ok","detail":"Authenticated Local API decisions endpoint reachable"})
        else:
            out.update({"status":"down","detail":f"CrowdSec API returned HTTP {r.status_code}"})
    except Exception as e: out.update({"status":"down","detail":f"{type(e).__name__}: {e}"})
    return out

async def _probe_falco() -> dict:
    started=time.monotonic(); out={"configured":True,"endpoint":f"{FALCO_HOST}:{FALCO_HEALTH_PORT}"}; writer=None
    try:
        reader,writer=await asyncio.wait_for(asyncio.open_connection(FALCO_HOST,FALCO_HEALTH_PORT),timeout=2)
        out.update({"status":"ok","detail":"Falco private health listener reachable","latency_ms":round((time.monotonic()-started)*1000)})
    except Exception as e: out.update({"status":"down","detail":f"{type(e).__name__}: {e}"})
    finally:
        if writer is not None:
            try: writer.close(); await writer.wait_closed()
            except Exception: pass
    return out

async def _probe_trivy() -> dict:
    started=time.monotonic(); out={"configured":True}
    try:
        code,version_out=await trivy_exec(["trivy","--version"],timeout=30)
        out.update({"status":"ok" if code==0 else "down","detail":version_out.strip()[-500:],"latency_ms":round((time.monotonic()-started)*1000)})
    except Exception as e: out.update({"status":"down","detail":f"{type(e).__name__}: {e}"})
    return out

async def _fresh_sensor_snapshot(record: bool=False, force: bool=False) -> dict[str,dict]:
    tmono=time.monotonic()
    if not force and _sensor_cache.get("data") and tmono-float(_sensor_cache.get("ts") or 0) < SENSOR_CACHE_TTL_SECONDS:
        return {k:dict(v) for k,v in _sensor_cache["data"].items()}
    async with _sensor_cache_lock:
        tmono=time.monotonic()
        if not force and _sensor_cache.get("data") and tmono-float(_sensor_cache.get("ts") or 0) < SENSOR_CACHE_TTL_SECONDS:
            return {k:dict(v) for k,v in _sensor_cache["data"].items()}
        vals=await asyncio.gather(_probe_clamav(),_probe_crowdsec(),_probe_falco(),_probe_trivy())
        result=dict(zip(("clamav","crowdsec","falco","trivy"),vals))
        _sensor_cache.update({"ts":time.monotonic(),"data":result})
        if record:
            t=now()
            with conn() as c:
                for name,d in result.items():
                    c.execute("INSERT INTO sensor_health_history(ts,sensor,status,detail,latency_ms) VALUES(?,?,?,?,?)",(t,name,str(d.get('status') or 'unknown'),str(d.get('detail') or '')[:2000],d.get('latency_ms')))
        return {k:dict(v) for k,v in result.items()}

@app.get("/api/security/sensors/{sensor}/diagnostics")
async def sensor_diagnostics(sensor: str, authorization: str | None = Header(default=None)):
    require_token(authorization); sensor=sensor.lower()
    if sensor not in {"clamav","crowdsec","falco","trivy"}: raise HTTPException(404,"Unknown sensor")
    snap=await _fresh_sensor_snapshot(record=True, force=True)
    with conn() as c:
        hist=rowdicts(c.execute("SELECT ts,status,detail,latency_ms FROM sensor_health_history WHERE sensor=? ORDER BY id DESC LIMIT 12",(sensor,)).fetchall())
    return {"sensor":sensor,"current":snap[sensor],"history":hist,"failure_grace_seconds":SENSOR_FAILURE_GRACE_SECONDS}

@app.get("/api/integrations")
async def integrations(authorization: str | None = Header(default=None)):
    require_token(authorization)
    sensor_health=await _fresh_sensor_snapshot(record=False)
    result = {
        "clamav": dict(sensor_health["clamav"]),
        "crowdsec": dict(sensor_health["crowdsec"]),
        "falco": dict(sensor_health["falco"]),
        "trivy": dict(sensor_health["trivy"]),
        "discord": {"configured": bool(DISCORD_WEBHOOK)},
        "n8n": {"configured": bool(N8N_WEBHOOK)},
    }
    with conn() as c:
        f = c.execute("SELECT ts,severity,container_name,message FROM security_events WHERE source='falco' ORDER BY id DESC LIMIT 1").fetchone()
        counts = c.execute("SELECT severity,count(*) n FROM security_events WHERE source='falco' AND ts>? GROUP BY severity", (now()-86400,)).fetchall()
    result["falco"]["events_24h"] = sum(r["n"] for r in counts)
    result["falco"]["counts_24h"] = {r["severity"]: r["n"] for r in counts}
    if f:
        result["falco"]["last_event_ts"] = f["ts"]
        result["falco"]["last_event_age_seconds"] = max(0, now() - int(f["ts"]))
        result["falco"]["last_container"] = f["container_name"]
        result["falco"]["last_severity"] = f["severity"]
    with conn() as c:
        t = c.execute("SELECT ts,container_name,image,status,critical,high,medium FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        tc = c.execute("SELECT count(*) n,coalesce(sum(critical),0) critical,coalesce(sum(high),0) high,coalesce(sum(medium),0) medium FROM scans WHERE ts>?", (now()-86400,)).fetchone()
    result["trivy"]["scans_24h"] = tc["n"]
    result["trivy"]["critical_24h"] = tc["critical"]
    result["trivy"]["high_24h"] = tc["high"]
    if t:
        result["trivy"]["last_scan_ts"] = t["ts"]
        result["trivy"]["last_container"] = t["container_name"]
        result["trivy"]["last_scan_status"] = t["status"]
    return result


@app.get("/api/security/falco/summary")
async def falco_summary(authorization: str | None = Header(default=None)):
    require_token(authorization)
    cutoff = now() - 86400
    with conn() as c:
        rows = c.execute("SELECT id,ts,severity,container_name,message,raw_json FROM security_events WHERE source='falco' ORDER BY id DESC LIMIT 20").fetchall()
        counts = c.execute("SELECT severity,count(*) n FROM security_events WHERE source='falco' AND ts>? GROUP BY severity", (cutoff,)).fetchall()
        rule_rows = c.execute("SELECT raw_json FROM security_events WHERE source='falco' AND ts>? ORDER BY id DESC LIMIT 2000", (cutoff,)).fetchall()
        latest = c.execute("SELECT ts FROM security_events WHERE source='falco' ORDER BY id DESC LIMIT 1").fetchone()
    recent=[]
    for r in rows:
        d=dict(r); raw=d.pop("raw_json", None); rule=None
        try:
            rule=(json.loads(raw or "{}") or {}).get("rule")
        except Exception:
            pass
        d["rule"] = rule or "Falco event"
        recent.append(d)
    grouped={}
    for r in rule_rows:
        try:
            raw=json.loads(r["raw_json"] or "{}")
            rule=str(raw.get("rule") or "Falco event")
            grouped[rule]=grouped.get(rule,0)+1
        except Exception:
            grouped["Falco event"]=grouped.get("Falco event",0)+1
    top_rules=[{"rule":k,"count":v} for k,v in sorted(grouped.items(), key=lambda kv: kv[1], reverse=True)[:6]]
    return {"events_24h": sum(r["n"] for r in counts), "counts_24h": {r["severity"]: r["n"] for r in counts},
            "last_event_ts": latest["ts"] if latest else None, "last_event_age_seconds": max(0, now()-latest["ts"]) if latest else None,
            "top_rules_24h": top_rules, "recent": recent}


@app.get("/api/security/trivy/summary")
async def trivy_summary(authorization: str | None = Header(default=None)):
    require_token(authorization)
    start = now() - 86400
    with conn() as c:
        scans = c.execute("SELECT id,ts,container_name,image,status,critical,high,medium FROM scans ORDER BY id DESC LIMIT 20").fetchall()
        counts = c.execute("SELECT count(*) n,coalesce(sum(critical),0) critical,coalesce(sum(high),0) high,coalesce(sum(medium),0) medium FROM scans WHERE ts>?", (start,)).fetchone()
        findings = c.execute("""SELECT sf.scan_id,sf.container_name,sf.image,sf.vuln_id,sf.pkg_name,sf.installed_version,sf.fixed_version,sf.severity,sf.title
                              FROM scan_findings sf JOIN scans s ON s.id=sf.scan_id
                              WHERE s.ts>? AND sf.severity IN ('critical','high')
                              ORDER BY CASE sf.severity WHEN 'critical' THEN 0 ELSE 1 END, sf.id DESC LIMIT 30""", (start,)).fetchall()
    with conn() as c:
        sched_rows=c.execute("SELECT key,value FROM settings WHERE key LIKE 'trivy_scheduler_%'").fetchall()
    scheduler={r["key"].replace("trivy_scheduler_",""):r["value"] for r in sched_rows}
    return {"scans_24h": counts["n"], "critical_24h": counts["critical"], "high_24h": counts["high"],
            "medium_24h": counts["medium"], "recent_scans": rowdicts(scans), "top_findings": rowdicts(findings),
            "scheduler": scheduler, "auto_scan_enabled": TRIVY_AUTO_SCAN_ENABLED}


@app.get("/api/decision-engine/summary")
async def decision_engine_summary(authorization: str | None = Header(default=None)):
    require_token(authorization)
    cutoff24 = now()-86400
    cutoffwin = now()-DECISION_WINDOW_SECONDS
    with conn() as c:
        recent = c.execute("SELECT id,ts,container_name,score,risk,sources_json,action,executed,result FROM correlation_runs ORDER BY id DESC LIMIT 15").fetchall()
        counts = c.execute("SELECT risk,count(*) n FROM correlation_runs WHERE ts>? GROUP BY risk", (cutoff24,)).fetchall()
        srcrows = c.execute("SELECT source,count(*) n FROM security_events WHERE ts>? GROUP BY source", (cutoffwin,)).fetchall()
        trivy24 = c.execute("SELECT count(*) n FROM scans WHERE ts>?", (cutoff24,)).fetchone()["n"]
    items=[]
    for r in recent:
        d=dict(r)
        try: d["sources"] = json.loads(d.pop("sources_json"))
        except Exception: d["sources"] = []
        items.append(d)
    cmap={r["risk"]:r["n"] for r in counts}
    active={r["source"]:r["n"] for r in srcrows}
    escalations=sum(v for k,v in cmap.items() if k in {"medium","high","critical"})
    if not active and not trivy24:
        explanation="No recent security signals and no Trivy scans yet. The engine is idle, not broken."
    elif set(active.keys()) == {"falco"} and not trivy24:
        explanation=f"Falco is producing alerts, but it is only one independent source and Trivy has 0 scans. Repeated Falco alerts are intentionally not multiplied into compromise risk."
    elif len(active) <= 1:
        explanation="Only one active runtime source is contributing right now. Kingdom Manager records it but waits for independent corroboration before escalation."
    else:
        explanation=f"Independent evidence is active from {', '.join(sorted(active))}. Correlation decisions will escalate only when score and source thresholds are met."
    return {"window_seconds": DECISION_WINDOW_SECONDS, "counts_24h": cmap, "escalations_24h": escalations,
            "active_sources_window": active, "trivy_scans_24h": trivy24, "explanation": explanation, "recent": items}


async def core_sensor_health() -> dict[str, dict]:
    """Single canonical live health snapshot used by scoring and UI engine state."""
    return await _fresh_sensor_snapshot(record=True)


@app.get("/api/security/score")
async def security_score(authorization: str | None = Header(default=None)):
    require_token(authorization)
    if _api_snapshot.get("score") and time.monotonic()-float(_api_snapshot.get("ts") or 0) < API_SNAPSHOT_TTL_SECONDS:
        return json.loads(json.dumps(_api_snapshot["score"], default=str))
    t=now(); cutoff=t-86400
    containers=await list_containers()
    with conn() as c:
        corr=c.execute("SELECT container_name,score,risk,action,ts,sources_json,signals_json FROM correlation_runs WHERE ts>? ORDER BY ts DESC",(cutoff,)).fetchall()
        scans=c.execute("SELECT container_name,critical,high,medium,ts FROM scans WHERE status='ok' AND ts>? ORDER BY ts DESC",(t-TRIVY_CONTEXT_SECONDS,)).fetchall()
        falco=c.execute("SELECT container_name,severity,message,ts FROM security_events WHERE source='falco' AND ts>? ORDER BY ts DESC",(cutoff,)).fetchall()
        sup=0  # populated from active suppression diagnostics below
    latest_corr={}
    for r in corr:
        key=r['container_name'] or 'host'
        if key not in latest_corr: latest_corr[key]=dict(r)
    latest_scan={}
    for r in scans:
        if r['container_name'] and r['container_name'] not in latest_scan: latest_scan[r['container_name']]=dict(r)
    try:
        sup_diag=suppression_diagnostics_data()
        sup=sum(int(x.get('matching_events_24h') or 0) for x in sup_diag if x.get('active'))
    except Exception:
        sup_diag=[]; sup=0
    severity_counts={'critical':0,'high':0,'medium':0,'low':0}
    leaderboard=[]; immediate=[]
    for item in containers:
        name=item['name']; profile=risk_profile(name); raw=0; factors=[]
        cr=latest_corr.get(name)
        live_ctx=current_security_context(name)
        if cr or live_ctx.get('original') or live_ctx.get('suppressed'):
            # Live evidence is canonical whenever it exists. Historical correlation
            # is only a fallback when the current decision window is quiet.
            if live_ctx.get('original') or live_ctx.get('suppressed'):
                cr_ctx=live_ctx
                original_cr_score=int(live_ctx.get('original') or 0); cr_score=int(live_ctx.get('effective') or 0)
                src_list=list(live_ctx.get('raw_sources') or [])
            else:
                cr_ctx=suppression_aware_correlation(name,cr)
                original_cr_score=cr_ctx['original']; cr_score=cr_ctx['effective']
                try: src_list=json.loads(cr['sources_json'] or '[]')
                except Exception: src_list=[]
            if cr_ctx['suppressed']:
                adj=max(0,original_cr_score-cr_score)
                scopes=', '.join(str(x.get('rule') or x.get('source')) for x in cr_ctx['suppressed'][:2])
                factors.append(f"Known-good approval APPLIED: original {original_cr_score} − {adj} = {cr_score} effective risk points ({scopes})")
            # Adaptive baseline attenuation is deliberately narrow: Falco-only, established
            # recurring behavior, a recent successful clean Trivy scan, and no explicit
            # known-good attenuation already applied to the same stored run.
            elif src_list==['falco'] or set(src_list)=={'falco'}:
                with conn() as c:
                    top_ev=c.execute("SELECT message,raw_json FROM security_events WHERE source='falco' AND container_name=? AND ts>? ORDER BY ts DESC LIMIT 1",(name,t-86400)).fetchone()
                if top_ev:
                    rawj=_safe_json(top_ev['raw_json'],{}) or {}; brule=str(rawj.get('rule') or falco_rule_from_message(top_ev['message']) or '')
                    b=falco_baseline_metrics(name,brule,BASELINE_DAYS)
                    scx=latest_scan.get(name)
                    clean=bool(scx and not int(scx.get('critical') or 0) and not int(scx.get('high') or 0) and not int(scx.get('medium') or 0))
                    if clean and b.get('status') in {'stable','learning'}:
                        adj=BASELINE_STABLE_ATTENUATION if b['status']=='stable' else BASELINE_LEARNING_ATTENUATION
                        cr_score=max(KNOWN_GOOD_RESIDUAL_RISK,cr_score-adj)
                        factors.append(f"Adaptive baseline: {b['status']} Falco behavior ({b['count']} events/{b['span_hours']}h), −{adj} risk points")
                    elif b.get('status')=='novel' and str(top_ev['message']):
                        factors.append('Adaptive baseline: novel Falco behavior — no attenuation')
            raw=max(raw,cr_score)
            # Severity counters describe effective Kingdom risk after suppression/baseline context.
            effective_risk='low' if cr_score<30 else ('medium' if cr_score<60 else ('high' if cr_score<90 else 'critical'))
            if cr_score > 0 and effective_risk in severity_counts: severity_counts[effective_risk]+=1
            if cr_score > 0:
                remaining=cr_ctx.get('remaining_sources') or src_list
                srcs=', '.join(remaining) if isinstance(remaining,list) else 'security evidence'
                factors.append(f"Decision Engine: {effective_risk} ({cr_score} effective risk points; {srcs or 'known-good residual'})")
        sc=latest_scan.get(name)
        if sc:
            vuln=min(35, int(sc['critical'])*12 + int(sc['high'])*4 + min(int(sc['medium']),10))
            raw=max(raw,vuln)
            if sc['critical']: factors.append(f"Trivy: {sc['critical']} critical CVE(s)")
            elif sc['high']: factors.append(f"Trivy: {sc['high']} high CVE(s)")
        weighted=min(100,round(raw*float(profile['weight'])))
        score=max(0,100-weighted)
        if score>=90: state='healthy'
        elif score>=75: state='watch'
        elif score>=55: state='elevated'
        elif score>=35: state='high risk'
        else: state='critical'
        row={'container':name,'score':score,'risk':weighted,'state':state,'profile':profile['profile'],'weight':profile['weight'],'factors':factors[:3] or ['No active risk deductions']}
        leaderboard.append(row)
        if score<55: immediate.append(row)
    leaderboard.sort(key=lambda x:(x['score'],x['container']))
    # Server score is driven by the worst containers plus breadth, not raw event count.
    risks=sorted((x['risk'] for x in leaderboard), reverse=True)
    penalty=(risks[0] if risks else 0)*0.55 + (risks[1] if len(risks)>1 else 0)*0.20 + min(sum(1 for r in risks if r>=25)*2,10)
    server_score=max(0,min(100,round(100-penalty)))

    # Monitoring confidence matters. A server cannot honestly be 100/100 while
    # one of its core sensors is unavailable, even if there is no active threat.
    sensor_health = await core_sensor_health()
    sensor_penalties = {"falco": 12, "clamav": 10, "crowdsec": 9, "trivy": 8}
    unavailable = [name for name, data in sensor_health.items() if data.get("status") != "ok"]
    confidence_penalty = sum(sensor_penalties.get(name, 5) for name in unavailable)
    # v3 canonical overall score: weighted independent posture dimensions. Sensor outages
    # affect Monitoring once, avoiding the previous double-penalty problem.
    dimensions=_risk_dimensions(leaderboard,sensor_health,latest_scan,containers)
    server_score=round(dimensions['threat']*0.35 + dimensions['vulnerability']*0.20 + dimensions['exposure']*0.15 + dimensions['monitoring']*0.20 + dimensions['trust']*0.10)
    server_score=max(0,min(100,server_score))

    if server_score>=90: mood,status,risk='excellent','EXCELLENT','LOW'
    elif server_score>=75: mood,status,risk='good','GOOD','LOW'
    elif server_score>=55: mood,status,risk='elevated','ELEVATED','MEDIUM'
    elif server_score>=35: mood,status,risk='high','HIGH RISK','HIGH'
    else: mood,status,risk='critical','CRITICAL','CRITICAL'
    if unavailable and server_score>=55:
        status='MONITORING DEGRADED'
    result={'score':server_score,'mood':mood,'status':status,'overall_risk':risk,'severity_counts':severity_counts,
            'immediate_attention':immediate[:6],'leaderboard':leaderboard[:12],'suppressed_24h':sup,'evaluated_ts':t,
            'sensor_health':sensor_health,'unavailable_sensors':unavailable,'monitoring_confidence':max(0,100-confidence_penalty),
            'dimensions':dimensions,'dimension_weights':{'threat':35,'vulnerability':20,'exposure':15,'monitoring':20,'trust':10},'risk_model':'kingdom-3.0-five-dimension-v2'}
    _api_snapshot.update({'ts':time.monotonic(),'score':result})
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        tmp=DASHBOARD_SNAPSHOT_PATH.with_suffix('.tmp')
        tmp.write_text(json.dumps({'saved_ts':now(),'score':result},default=str))
        tmp.replace(DASHBOARD_SNAPSHOT_PATH)
    except Exception:
        pass
    return json.loads(json.dumps(result, default=str))



def _risk_dimensions(leaderboard: list[dict], sensor_health: dict, latest_scan: dict, containers: list[dict]) -> dict:
    """Five independent 0..100 posture dimensions. Avoids double-counting event volume."""
    risks=sorted((int(x.get('risk') or 0) for x in leaderboard),reverse=True)
    threat=max(0,100-round((risks[0] if risks else 0)*0.75 + (risks[1] if len(risks)>1 else 0)*0.15))
    vuln_penalty=0
    for sc in latest_scan.values():
        vuln_penalty=max(vuln_penalty,min(100,int(sc.get('critical') or 0)*20+int(sc.get('high') or 0)*7+min(20,int(sc.get('medium') or 0))))
    vulnerability=max(0,100-vuln_penalty)
    weights={'falco':25,'clamav':25,'crowdsec':25,'trivy':25}
    monitoring=max(0,100-sum(weights.get(k,10) for k,v in sensor_health.items() if v.get('status')!='ok'))
    # Exposure uses actual published host ports plus high-risk Docker configuration indicators available in summary metadata.
    published=sum(1 for c in containers for p in (c.get('ports') or []) if p.get('PublicPort') is not None)
    core_published=sum(1 for c in containers if risk_profile(c.get('name','')).get('profile') in {'database','security','critical-infrastructure'} for p in (c.get('ports') or []) if p.get('PublicPort') is not None)
    exposure=max(0,100-min(70,published*2+core_published*8))
    # Trust measures how much current risk has explicit/scoped evidence handling, not general container health.
    active_risk=[x for x in leaderboard if int(x.get('risk') or 0)>0]
    explained=sum(1 for x in active_risk if any(('Known-good approval' in f or 'Adaptive baseline' in f or 'Trivy:' in f) for f in x.get('factors',[])))
    trust=100 if not active_risk else round(70+30*explained/max(1,len(active_risk)))
    return {'threat':threat,'vulnerability':vulnerability,'exposure':exposure,'monitoring':monitoring,'trust':min(100,trust),
            'evidence':{'published_ports':published,'core_published_ports':core_published,'active_risk_containers':len(active_risk),'explained_risk_containers':explained}}

def _playbook_for_incident(inc: dict, investigation: dict | None=None) -> dict:
    sources=set(_safe_json(inc.get('sources_json'),[]) or [])
    sev=str(inc.get('severity') or 'low').lower(); name=inc.get('container_name') or 'host'
    inv=investigation or {}; classification=str(inv.get('classification') or '').lower()
    steps=[]
    def add(key,title,gate='operator',destructive=False,auto=False):
        steps.append({'key':key,'title':title,'gate':gate,'destructive':destructive,'auto_eligible':auto})
    add('capture','Capture immutable incident/container evidence','automatic',False,PLAYBOOK_AUTO_EVIDENCE)
    if name!='host': add('scan','Refresh Trivy image verification','automatic',False,PLAYBOOK_AUTO_SCAN)
    add('correlate','Recalculate Falco / Trivy / ClamAV / CrowdSec corroboration','automatic',False,True)
    if 'clamav' in sources: add('malware-review','Preserve malware/quarantine evidence','operator')
    if len(sources)>=2 or sev in {'critical','high'}: add('isolate','Isolate container from production networks','policy',False,PLAYBOOK_AUTO_ISOLATE)
    if classification in {'likely-expected','expected','likely expected'}: add('baseline','Review exact Falco rule and scoped known-good approval','operator')
    else: add('investigate','Review processes, image, network and corroboration evidence','operator')
    if name!='host': add('recover','Prepare controlled rebuild plan','approval',True,PLAYBOOK_AUTO_RECOVER)
    add('observe','Post-action health and sensor observation','automatic',False,True)
    add('resolve','Resolve incident with audit note','operator')
    return {'name':'Kingdom 2.1 adaptive response','enabled':PLAYBOOKS_ENABLED,'container':name,'severity':sev,'sources':sorted(sources),'classification':classification,'steps':steps,'destructive_actions_require_approval':True,'safe_auto_steps':[x['key'] for x in steps if x['auto_eligible'] and not x['destructive'] and x['key'] in {'capture','scan','correlate','observe'}]}

@app.get("/api/security/posture")
async def security_posture(authorization: str | None = Header(default=None)):
    require_token(authorization)
    score=await security_score(authorization)
    return {'version':VERSION,'score':score['score'],'dimensions':score.get('dimensions',{}),'sensor_health':score.get('sensor_health',{}),'recovery_model':'evidence-gated','policy_model':'per-container + risk-profile','automation_boundary':'safe playbook steps may run automatically; destructive recovery requires explicit approval','playbooks':{'enabled':PLAYBOOKS_ENABLED,'auto_evidence':PLAYBOOK_AUTO_EVIDENCE,'auto_scan':PLAYBOOK_AUTO_SCAN,'auto_isolate':PLAYBOOK_AUTO_ISOLATE,'auto_recover':PLAYBOOK_AUTO_RECOVER}}

@app.get("/api/incidents/{incident_id}/playbook")
async def incident_playbook(incident_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c:
        r=c.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
    if not r: raise HTTPException(404,'Incident not found')
    inv=await build_incident_investigation(incident_id,persist=False)
    return _playbook_for_incident(dict(r),inv)

@app.post("/api/incidents/{incident_id}/playbook/run-safe")
async def run_safe_playbook(incident_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    if not PLAYBOOKS_ENABLED: raise HTTPException(409,'Playbooks are disabled')
    with conn() as c: inc=c.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
    if not inc: raise HTTPException(404,'Incident not found')
    inv=await build_incident_investigation(incident_id,persist=False); plan=_playbook_for_incident(dict(inc),inv)
    t=now()
    with conn() as c:
        cur=c.execute("INSERT INTO playbook_runs(incident_id,created_ts,status,plan_json,result_json) VALUES(?,?,?,?,?)",(incident_id,t,'running',json.dumps(plan),json.dumps({})))
        run_id=cur.lastrowid
    result={'run_id':run_id,'incident_id':incident_id,'completed':[],'skipped':[],'errors':[]}
    name=inc['container_name']
    try:
        if PLAYBOOK_AUTO_EVIDENCE:
            try: result['evidence']=await capture_incident_evidence(incident_id,f"Bearer {API_TOKEN}"); result['completed'].append('capture')
            except Exception as e: result['errors'].append('capture: '+str(e))
        else: result['skipped'].append('capture')
        # capture_incident_evidence already runs Trivy for containers; only run a separate scan when evidence capture is disabled.
        if name and PLAYBOOK_AUTO_SCAN and not PLAYBOOK_AUTO_EVIDENCE:
            try: result['scan']=await trivy_scan(name); result['completed'].append('scan')
            except Exception as e: result['errors'].append('scan: '+str(e))
        elif name and PLAYBOOK_AUTO_SCAN: result['completed'].append('scan')
        elif name: result['skipped'].append('scan')
        result['assessment']=await build_incident_investigation(incident_id,True); result['completed'].append('correlate')
        result['sensor_health']=await core_sensor_health(); result['completed'].append('observe')
        result['requires_operator']=[x for x in plan['steps'] if x['gate'] in {'operator','policy','approval'}]
        status='completed-with-warnings' if result['errors'] else 'completed'
        with conn() as c: c.execute("UPDATE playbook_runs SET completed_ts=?,status=?,result_json=? WHERE id=?",(now(),status,json.dumps(result,default=str),run_id))
        event('playbook',name or 'host',{'run_id':run_id,'incident_id':incident_id,'status':status,'completed':result['completed'],'errors':result['errors']},'warning' if result['errors'] else 'info')
        return {'ok':not bool(result['errors']),'status':status,'plan':plan,**result}
    except Exception as e:
        result['errors'].append(str(e))
        with conn() as c: c.execute("UPDATE playbook_runs SET completed_ts=?,status='failed',result_json=? WHERE id=?",(now(),json.dumps(result,default=str),run_id))
        raise HTTPException(500,result)

@app.get("/api/incidents/{incident_id}/playbook/runs")
async def playbook_run_history(incident_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: rows=c.execute("SELECT id,created_ts,completed_ts,status,plan_json,result_json FROM playbook_runs WHERE incident_id=? ORDER BY id DESC LIMIT 20",(incident_id,)).fetchall()
    out=[]
    for r in rows:
        d=dict(r); d['plan']=_safe_json(d.pop('plan_json'),{}); d['result']=_safe_json(d.pop('result_json'),{}); out.append(d)
    return out

def suppression_diagnostics_data() -> list[dict]:
    t=now(); cutoff=t-86400; out=[]
    with conn() as c:
        sups=c.execute("SELECT id,enabled,source,container_name,rule_contains,reason,expires_ts,created_ts FROM suppressions ORDER BY id DESC").fetchall()
    for sr in sups:
        d=dict(sr); source=str(d.get('source') or '').lower(); name=d.get('container_name') or ''; rule=str(d.get('rule_contains') or '')
        active=bool(d.get('enabled')) and (d.get('expires_ts') is None or int(d.get('expires_ts') or 0)>t)
        matches=0; sample=''; correlation_matches=0; points_removed=0; blocker=''
        if active and name:
            with conn() as c:
                rows=c.execute("SELECT ts,message,raw_json,severity FROM security_events WHERE source=? AND container_name=? AND ts>? ORDER BY id DESC",(source,name,cutoff)).fetchall()
                crs=c.execute("SELECT score,signals_json,sources_json,ts FROM correlation_runs WHERE container_name=? AND ts>? ORDER BY id DESC LIMIT 25",(name,cutoff)).fetchall()
            for r in rows:
                raw=_safe_json(r['raw_json'],{}) or {}; rr=str(raw.get('rule') or (falco_rule_from_message(r['message']) if source=='falco' else '') or '')
                if active_suppression(source,name,str(r['message'] or ''),rule=rr) and normalize_rule(rule)==normalize_rule(active_suppression(source,name,str(r['message'] or ''),rule=rr).get('rule_contains') or ''):
                    matches+=1
                    if not sample: sample=rr or str(r['message'] or '')[:180]
            live=current_security_context(name)
            if any(normalize_rule(str(x.get('rule') or ''))==normalize_rule(rule) for x in live.get('suppressed',[])):
                correlation_matches+=1
                points_removed=max(points_removed,int(live.get('original') or 0)-int(live.get('effective') or 0))
            for cr in crs:
                ctx=suppression_aware_correlation(name,dict(cr))
                if ctx.get('suppressed'):
                    correlation_matches+=1
                    points_removed=max(points_removed,int(ctx.get('original') or 0)-int(ctx.get('effective') or 0))
            d['live_original_risk']=int(live.get('original') or 0)
            d['live_effective_risk']=int(live.get('effective') or 0)
            d['live_remaining_sources']=live.get('remaining_sources') or []
            if matches==0:
                blocker='No recent event matched this exact container + rule scope'
            elif not any(normalize_rule(str(x.get('rule') or ''))==normalize_rule(rule) for x in live.get('suppressed',[])):
                blocker='Approval matches historical events, but no matching signal is inside the current decision window'
        elif not active:
            blocker='Suppression is disabled or expired'
        d.update({'active':active,'matching_events_24h':matches,'matching_correlations_24h':correlation_matches,'points_removed':points_removed,'sample_match':sample,'blocker':blocker})
        out.append(d)
    return out


@app.get("/api/suppressions/diagnostics")
async def suppression_diagnostics(authorization: str | None = Header(default=None)):
    require_token(authorization)
    rows=suppression_diagnostics_data()
    return {'active':sum(1 for x in rows if x['active']),'matching_events_24h':sum(int(x['matching_events_24h']) for x in rows if x['active']),'points_removed':sum(int(x['points_removed']) for x in rows if x['active']),'rows':rows}


@app.get("/api/suppressions")
async def get_suppressions(authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: return rowdicts(c.execute('SELECT * FROM suppressions ORDER BY id DESC').fetchall())

@app.post("/api/suppressions/preview")
async def suppression_preview(request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json()
    source=str(d.get('source','falco')).lower(); name=d.get('container_name'); rule=str(d.get('rule_contains','')).strip()
    if not name or not rule: raise HTTPException(400,'container_name and rule_contains are required')
    cutoff=now()-86400
    with conn() as c:
        rows=c.execute("SELECT severity,message,raw_json FROM security_events WHERE source=? AND container_name=? AND ts>?",(source,name,cutoff)).fetchall()
        riskrow=c.execute("SELECT score,risk FROM correlation_runs WHERE container_name=? ORDER BY id DESC LIMIT 1",(name,)).fetchone()
    matches=0; severities={}
    for r in rows:
        raw=_safe_json(r['raw_json'],{}) or {}; rr=str(raw.get('rule') or falco_rule_from_message(r['message']) or '')
        if rule.lower() in rr.lower() or rule.lower() in str(r['message']).lower():
            matches+=1; sev=str(r['severity']).lower(); severities[sev]=severities.get(sev,0)+1
    estimated_points=int(riskrow['score'] or 0) if riskrow else 0
    return {'source':source,'container':name,'rule':rule,'matching_events_24h':matches,'severity_counts':severities,'estimated_current_risk_points':estimated_points,'scope':f'container={name} + rule={rule}','global':False}

@app.post("/api/suppressions")
async def add_suppression(request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json()
    source=str(d.get('source','falco')).lower(); name=d.get('container_name'); rule=str(d.get('rule_contains','')).strip(); reason=str(d.get('reason','known-good behavior'))
    expires_hours=d.get('expires_hours'); expires_ts=None
    if expires_hours not in (None,'',0,'0'):
        expires_ts=now()+max(1,min(int(expires_hours),24*365))*3600
    if not name: raise HTTPException(400,'container_name is required; global suppressions are intentionally blocked')
    if not rule: raise HTTPException(400,'rule_contains is required')
    with conn() as c:
        c.execute('INSERT INTO suppressions(enabled,source,container_name,rule_contains,reason,expires_ts,created_ts) VALUES(1,?,?,?,?,?,?) ON CONFLICT(source,container_name,rule_contains) DO UPDATE SET enabled=1,reason=excluded.reason,expires_ts=excluded.expires_ts,created_ts=excluded.created_ts',(source,name,rule,reason,expires_ts,now()))
    event('suppression',name,{'source':source,'rule':rule,'reason':reason,'expires_ts':expires_ts})
    return {'ok':True,'scope':f'container={name} + rule={rule}','expires_ts':expires_ts}

@app.put("/api/risk-profiles/{name}")
async def set_risk_profile(name: str, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json(); profile=str(d.get('profile','user-app')); weight=float(d.get('weight',1.0))
    if not 0.2 <= weight <= 2.0: raise HTTPException(400,'weight must be between 0.2 and 2.0')
    with conn() as c: c.execute('INSERT OR REPLACE INTO risk_profiles(container_name,profile,weight) VALUES(?,?,?)',(name,profile,weight))
    event('risk_profile',name,{'profile':profile,'weight':weight})
    return {'container':name,'profile':profile,'weight':weight}



async def build_incident_investigation(incident_id: int, persist: bool = True) -> dict:
    with conn() as c:
        inc=c.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
    if not inc: raise HTTPException(404,'Incident not found')
    name=inc['container_name']; t=now(); factors=[]; falco_rules=[]
    with conn() as c:
        sec=c.execute("SELECT source,severity,message,raw_json,ts FROM security_events WHERE coalesce(container_name,'host')=? AND ts>? ORDER BY ts DESC",(name or 'host',t-86400)).fetchall()
        scan_attempt=c.execute("SELECT id,ts,image,status,critical,high,medium,result_json FROM scans WHERE container_name=? ORDER BY id DESC LIMIT 1",(name,)).fetchone() if name else None
        scan=c.execute("SELECT id,ts,image,status,critical,high,medium,result_json FROM scans WHERE container_name=? AND status='ok' ORDER BY id DESC LIMIT 1",(name,)).fetchone() if name else None
        suppressions=c.execute("SELECT source,container_name,rule_contains,reason,expires_ts FROM suppressions WHERE enabled=1 AND (expires_ts IS NULL OR expires_ts>?) AND (container_name=? OR container_name IS NULL OR container_name='')",(t,name or '',)).fetchall()
        falco_total_24h=c.execute("SELECT count(*) n FROM security_events WHERE source='falco' AND ts>?",(t-86400,)).fetchone()['n']
        prior=c.execute("SELECT confidence,classification,score_snapshot,ts FROM incident_assessments WHERE incident_id=? ORDER BY id DESC LIMIT 1",(incident_id,)).fetchone()
    source_counts={}; strongest={}; first_ts=None; last_ts=None
    for r in sec:
        src=str(r['source']).lower(); source_counts[src]=source_counts.get(src,0)+1
        first_ts=min(first_ts or int(r['ts']),int(r['ts'])); last_ts=max(last_ts or 0,int(r['ts']))
        sev=str(r['severity']).lower(); rank={'critical':5,'high':4,'warning':3,'medium':3,'notice':2,'info':1,'low':1}.get(sev,1)
        if src not in strongest or rank>strongest[src]['rank']: strongest[src]={'severity':sev,'message':r['message'],'rank':rank}
        if src=='falco':
            raw=_safe_json(r['raw_json'],{}) or {}; rule=raw.get('rule') or falco_rule_from_message(r['message']) or 'Other Falco rule'
            fields=raw.get('output_fields') or {}
            sample={
                'proc_exe': fields.get('proc.exepath') or fields.get('proc.exe') or '',
                'process': fields.get('proc.name') or '',
                'parent': fields.get('proc.pname') or '',
                'cmdline': fields.get('proc.cmdline') or '',
                'user': fields.get('user.name') or '',
                'image': ((fields.get('container.image.repository') or '') + ((':' + str(fields.get('container.image.tag'))) if fields.get('container.image.tag') else '')),
                'fd': fields.get('fd.name') or '',
                'ts': int(r['ts']),
            }
            item=next((x for x in falco_rules if x['rule']==rule),None)
            if item:
                item['count']+=1; item['last_ts']=max(item['last_ts'],int(r['ts'])); item['first_ts']=min(item['first_ts'],int(r['ts']))
                if sample not in item['samples'] and len(item['samples']) < 3: item['samples'].append(sample)
            else: falco_rules.append({'rule':rule,'count':1,'first_ts':int(r['ts']),'last_ts':int(r['ts']),'severity':sev,'samples':[sample]})
    falco_rules.sort(key=lambda x:x['count'],reverse=True)
    top_rule=falco_rules[0]['rule'] if falco_rules else ''
    active_sources=set(strongest)
    trivy_clean=bool(scan and str(scan['status']).lower()=='ok' and int(scan['critical'] or 0)==0 and int(scan['high'] or 0)==0 and int(scan['medium'] or 0)==0)
    trivy_no_critical_high=bool(scan and str(scan['status']).lower()=='ok' and int(scan['critical'] or 0)==0 and int(scan['high'] or 0)==0)
    trivy_risky=bool(scan and str(scan['status']).lower()=='ok' and (int(scan['critical'] or 0)>0 or int(scan['high'] or 0)>0))
    baseline=falco_baseline_metrics(name,top_rule,BASELINE_DAYS) if name and top_rule else {'status':'unknown','confidence':0,'count':0,'span_hours':0,'score_adjustment':0}
    expected_rule=active_suppression('falco',name,rule=top_rule) if name and top_rule else None
    latest_attempt=dict(scan_attempt) if scan_attempt else None
    malware=bool('clamav' in strongest and strongest['clamav']['severity'] in {'critical','high'})
    multi=len(active_sources)>=2
    confidence_math=[]
    if expected_rule and active_sources == {'falco'}:
        classification,confidence='likely-expected',95
        factors.append(f"Operator-approved known-good Falco rule: {top_rule}")
        exp=expected_rule.get('expires_ts')
        confidence_math.append({'points':23,'reason':'Exact container + Falco rule was explicitly approved as known-good'+(f" until {datetime.fromtimestamp(int(exp),TZ).isoformat()}" if exp else ''),'direction':'expected'})
        if trivy_clean:
            factors.append('Latest successful Trivy scan is clean')
        elif scan_attempt and str(scan_attempt['status']).lower()!='ok':
            factors.append('Latest Trivy attempt failed; last successful scan is used for context only')
    elif malware:
        classification,confidence='high-confidence-threat',96; factors.append('ClamAV supplied high-severity malware evidence'); confidence_math.append({'points':26,'reason':'High-severity ClamAV malware corroboration','direction':'threat'})
    elif multi and ('falco' in active_sources) and ('crowdsec' in active_sources or 'clamav' in active_sources):
        classification,confidence='suspicious',88; factors.append('Independent runtime and security-engine evidence corroborate each other'); confidence_math.append({'points':18,'reason':'Independent runtime + security-engine corroboration','direction':'threat'})
    elif multi or trivy_risky:
        classification,confidence='suspicious',78; factors.append('Multiple evidence sources or vulnerable image context require review'); confidence_math.append({'points':8,'reason':'Multiple sources or vulnerable image context','direction':'threat'})
    elif 'falco' in active_sources and source_counts.get('falco',0)>=25:
        classification,confidence='likely-expected',72; factors.append('High-volume repeated Falco-only behavior without corroboration'); confidence_math.append({'points':12,'reason':'Repeated container-specific Falco pattern','direction':'expected'})
        if trivy_clean:
            confidence=min(95,confidence+14); confidence_math.append({'points':14,'reason':'Recent Trivy scan is completely clean','direction':'expected'}); factors.append('Clean Trivy scan strengthens the likely-expected assessment')
        elif trivy_no_critical_high:
            confidence=min(92,confidence+9); confidence_math.append({'points':9,'reason':'Trivy found no critical/high vulnerabilities','direction':'expected'}); factors.append('Trivy found no critical/high vulnerabilities')
        if 'clamav' not in active_sources:
            confidence=min(95,confidence+4); confidence_math.append({'points':4,'reason':'No correlated ClamAV evidence','direction':'expected'})
        if 'crowdsec' not in active_sources:
            confidence=min(95,confidence+4); confidence_math.append({'points':4,'reason':'No correlated CrowdSec evidence','direction':'expected'})
        if baseline.get('status')=='stable':
            bonus=min(5,max(2,int(baseline.get('confidence',0)//25)))
            confidence=min(95,confidence+bonus); confidence_math.append({'points':bonus,'reason':f"Behavior baseline is stable across {baseline.get('span_hours',0)}h / {baseline.get('count',0)} events",'direction':'expected'}); factors.append('Adaptive baseline recognizes this as established recurring behavior')
        elif baseline.get('status')=='novel':
            confidence=max(55,confidence-6); confidence_math.append({'points':-6,'reason':'Behavior is novel to the 7-day container baseline','direction':'caution'}); factors.append('Behavior is novel to the current baseline')
    elif 'falco' in active_sources and trivy_no_critical_high:
        classification,confidence='likely-expected',82; factors.append('Falco-only behavior with a recent Trivy scan showing no critical/high CVEs'); confidence_math.append({'points':12,'reason':'Falco-only plus clean critical/high Trivy context','direction':'expected'})
    elif active_sources:
        classification,confidence='unverified',62; factors.append('Security evidence exists but is not independently corroborated')
    else:
        classification,confidence='low-evidence',70; factors.append('No recent active security evidence found for this incident subject')
    if last_ts:
        age_hours=max(0,(t-last_ts)/3600)
        if age_hours>=24:
            decay=min(15,int(age_hours//24)*3); confidence=max(50,confidence-decay); confidence_math.append({'points':-decay,'reason':f'Evidence is {age_hours:.0f}h old','direction':'freshness'})
    if falco_rules: factors.append(f"Top Falco rule: {top_rule} ×{falco_rules[0]['count']}")
    if scan: factors.append(f"Last successful Trivy: {scan['critical']} critical / {scan['high']} high / {scan['medium']} medium")
    if scan_attempt and str(scan_attempt['status']).lower()!='ok': factors.append('Latest Trivy attempt: SCAN ERROR')
    summary={
      'likely-expected':'Likely expected container behavior. Review the top rule and mark it expected only if you recognize it.',
      'suspicious':'Suspicious activity has supporting context and deserves investigation before recovery actions.',
      'high-confidence-threat':'Strong threat evidence detected. Capture evidence and isolate before considering recovery.',
      'unverified':'The signal is real but not sufficiently corroborated yet.',
      'low-evidence':'The incident has little recent evidence; review history before closing it.'
    }.get(classification,'Review required.')
    policy=default_policy(name) if name else None; rp=risk_profile(name) if name else None
    recovery_reasons=[]
    hard_protected={'kingdom-manager','kingdom-manager-docker-api','kingdom-manager-recovery-docker-api','kingdom-manager-trivy-docker-api','kingdom-manager-trivy'}
    if name in hard_protected: recovery_reasons.append('Kingdom core service is hard-protected')
    if policy and not policy.get('allow_rebuild'): recovery_reasons.append('Approved Rebuild is off')
    if policy and policy.get('protected'): recovery_reasons.append('Protected is on')
    if rp and rp.get('profile')=='database' and not RECOVERY_ALLOW_DATABASES: recovery_reasons.append('Database automated recovery is disabled')
    score_snapshot=(await security_score(f"Bearer {API_TOKEN}"))['score'] if API_TOKEN else None
    confidence_delta=(confidence-int(prior['confidence'])) if prior else 0
    score_delta=(score_snapshot-int(prior['score_snapshot'])) if prior and prior['score_snapshot'] is not None and score_snapshot is not None else 0
    matching_events=falco_rules[0]['count'] if falco_rules else 0
    intelligence=(f"{name or 'Host'} has {matching_events} matching Falco events for '{top_rule}'. " if top_rule else '')
    if classification=='likely-expected': intelligence+=f"No independent malware/network corroboration is active. Baseline state: {baseline.get('status','unknown').upper()} ({baseline.get('count',0)} matching events across {baseline.get('span_hours',0)}h). Kingdom currently rates this pattern LIKELY EXPECTED at {confidence}% confidence."
    elif classification in {'suspicious','high-confidence-threat'}: intelligence+=f"Independent evidence raises this to {classification.replace('-',' ').upper()} at {confidence}% confidence."
    else: intelligence+=f"Kingdom rates the incident {classification.replace('-',' ').upper()} at {confidence}% confidence."
    recommended_action=('monitor-expected' if expected_rule else ('mark-expected' if classification=='likely-expected' and confidence>=80 else ('capture-and-isolate' if classification in {'suspicious','high-confidence-threat'} else 'continue-investigation')))
    assessment={'incident_id':incident_id,'container':name,'classification':classification,'confidence':confidence,'confidence_delta':confidence_delta,'confidence_math':confidence_math,'summary':summary,'intelligence_summary':intelligence,'recommended_action':recommended_action,'factors':factors,'source_counts':source_counts,'strongest':strongest,'falco_rules':falco_rules[:10],'top_rule':top_rule,'matching_falco_events':matching_events,'falco_total_24h':int(falco_total_24h or 0),'first_observed':first_ts,'last_observed':last_ts,'latest_scan':dict(scan) if scan else None,'latest_scan_attempt':latest_attempt,'expected_rule':expected_rule,'policy':policy,'risk_profile':rp,'suppressions':rowdicts(suppressions),'recovery_available':bool(name and not recovery_reasons),'recovery_reasons':recovery_reasons,'score_snapshot':score_snapshot,'score_delta':score_delta,'baseline':baseline,'trivy_context':dict(scan) if scan else None}
    if persist:
        details={'confidence_math':confidence_math,'matching_falco_events':matching_events,'falco_total_24h':int(falco_total_24h or 0),'recommended_action':recommended_action,'baseline':baseline,'trivy_status':str(scan['status']) if scan else None}
        with conn() as c: c.execute("INSERT INTO incident_assessments(incident_id,ts,classification,confidence,summary,factors_json,top_rule,score_snapshot,details_json) VALUES(?,?,?,?,?,?,?,?,?)",(incident_id,t,classification,confidence,summary,json.dumps(factors),top_rule,score_snapshot,json.dumps(details)))
        event('investigation',name or 'host',{'incident_id':incident_id,'classification':classification,'confidence':confidence,'confidence_delta':confidence_delta,'score_delta':score_delta,'top_rule':top_rule})
    return assessment

@app.get("/api/incidents/{incident_id}/investigation")
async def incident_investigation(incident_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    return await build_incident_investigation(incident_id, True)

@app.post("/api/incidents/{incident_id}/scan")
async def incident_scan(incident_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: inc=c.execute("SELECT container_name FROM incidents WHERE id=?",(incident_id,)).fetchone()
    if not inc: raise HTTPException(404,'Incident not found')
    name=inc['container_name']
    if not name: raise HTTPException(409,'Host-only incident has no container image to scan')
    scan=await trivy_scan(name)
    assessment=await build_incident_investigation(incident_id, True)
    event('incident_scan',name,{'incident_id':incident_id,'scan_id':scan.get('scan_id'),'critical':scan.get('critical',0),'high':scan.get('high',0),'medium':scan.get('medium',0),'classification':assessment.get('classification'),'confidence':assessment.get('confidence')})
    return {'ok':True,'scan':scan,'assessment':assessment}

@app.post("/api/incidents/{incident_id}/mark-expected")
async def incident_mark_expected(incident_id: int, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json(); reason=str(d.get('reason','Known-good behavior approved by operator')); expires_hours=d.get('expires_hours'); expires_ts=(now()+max(1,min(int(expires_hours),24*365))*3600) if expires_hours not in (None,'',0,'0') else None
    assessment=await build_incident_investigation(incident_id, False); name=assessment.get('container'); rule=str(d.get('rule') or assessment.get('top_rule') or '')
    if not name or not rule: raise HTTPException(409,'No container-scoped Falco rule is available to suppress')
    with conn() as c:
        c.execute("INSERT INTO suppressions(enabled,source,container_name,rule_contains,reason,expires_ts,created_ts) VALUES(1,'falco',?,?,?,?,?) ON CONFLICT(source,container_name,rule_contains) DO UPDATE SET enabled=1,reason=excluded.reason,expires_ts=excluded.expires_ts,created_ts=excluded.created_ts",(name,rule,reason,expires_ts,now()))
        c.execute("UPDATE incidents SET status='dismissed',updated_ts=?,resolution=? WHERE id=?",(now(),f'Expected Falco behavior: {rule} — {reason}',incident_id))
    invalidate_security_snapshot(); event('suppression',name,{'incident_id':incident_id,'rule':rule,'reason':reason,'expires_ts':expires_ts})
    return {'ok':True,'incident_id':incident_id,'container':name,'rule':rule,'status':'dismissed','expires_ts':expires_ts}

@app.post("/api/incidents/{incident_id}/isolate")
async def incident_isolate(incident_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: inc=c.execute("SELECT container_name FROM incidents WHERE id=?",(incident_id,)).fetchone()
    if not inc or not inc['container_name']: raise HTTPException(404,'Incident/container not found')
    name=inc['container_name']; policy=default_policy(name)
    if policy['protected']: raise HTTPException(409,'Protected container cannot be isolated until protection is removed')
    result=await isolate(name)
    with conn() as c: c.execute("UPDATE incidents SET status='isolated',updated_ts=? WHERE id=?",(now(),incident_id))
    event('incident_isolated',name,{'incident_id':incident_id},'warning')
    return {'ok':True,'result':result}

@app.get("/api/incidents")
async def incidents(status: str = "active", severity: str = "", container: str = "", q: str = "", hours: int = 0, authorization: str | None = Header(default=None)):
    require_token(authorization)
    sql="SELECT * FROM incidents"; where=[]; args=[]
    if status=="active": where.append("status NOT IN ('resolved','dismissed')")
    elif status!="all": where.append("status=?"); args.append(status)
    if severity: where.append("severity=?"); args.append(severity.lower())
    if container: where.append("container_name=?"); args.append(container)
    if hours>0: where.append("updated_ts>?"); args.append(now()-min(hours,24*365)*3600)
    if q: where.append("(lower(coalesce(container_name,'')) LIKE ? OR lower(title) LIKE ? OR lower(coalesce(summary,'')) LIKE ?)"); pat='%'+q.lower()+'%'; args.extend([pat,pat,pat])
    if where: sql+=' WHERE '+' AND '.join(where)
    sql+=" ORDER BY updated_ts DESC LIMIT 200"
    with conn() as c: rows=c.execute(sql,args).fetchall()
    out=[]
    for r in rows:
        d=dict(r); d['sources']=json.loads(d.pop('sources_json') or '[]'); out.append(d)
    return out

@app.get("/api/incidents/{incident_id}")
async def incident_detail(incident_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c:
        r=c.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
        ev=c.execute("SELECT id,ts,evidence_type,label,payload FROM incident_evidence WHERE incident_id=? ORDER BY id",(incident_id,)).fetchall()
    if not r: raise HTTPException(404,'Incident not found')
    d=dict(r); d['sources']=json.loads(d.pop('sources_json') or '[]'); d['evidence']=rowdicts(ev); return d

@app.post("/api/incidents/{incident_id}/capture-evidence")
async def capture_incident_evidence(incident_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: inc=c.execute("SELECT * FROM incidents WHERE id=?",(incident_id,)).fetchone()
    if not inc: raise HTTPException(404,'Incident not found')
    name=inc['container_name']; captured=[]
    if name:
        obj=await inspect_container(name); sid=await snapshot(name,f'incident-{incident_id}')
        payload={'snapshot_id':sid,'image':obj.get('Config',{}).get('Image'),'image_id':obj.get('Image'),'networks':list((obj.get('NetworkSettings',{}).get('Networks') or {}).keys()),'mounts':obj.get('Mounts',[]),'state':obj.get('State',{})}
        with conn() as c: c.execute("INSERT INTO incident_evidence(incident_id,ts,evidence_type,label,payload) VALUES(?,?,?,?,?)",(incident_id,now(),'container_snapshot','Docker inspect',json.dumps(payload,default=str)[:100000]))
        captured.append('container_snapshot')
        try:
            scan=await trivy_scan(name)
            with conn() as c: c.execute("INSERT INTO incident_evidence(incident_id,ts,evidence_type,label,payload) VALUES(?,?,?,?,?)",(incident_id,now(),'trivy','On-demand Trivy scan',json.dumps(scan,default=str)[:100000]))
            captured.append('trivy')
        except Exception as e: captured.append('trivy_error:'+str(e))
    event('evidence',name or 'host',{'incident_id':incident_id,'captured':captured})
    return {'ok':True,'incident_id':incident_id,'captured':captured}

@app.post("/api/incidents/{incident_id}/resolve")
async def resolve_incident(incident_id: int, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json(); resolution=str(d.get('resolution','Resolved by operator'))
    with conn() as c: c.execute("UPDATE incidents SET status='resolved',updated_ts=?,resolution=? WHERE id=?",(now(),resolution,incident_id))
    event('incident','',{'id':incident_id,'action':'resolved','resolution':resolution}); return {'ok':True}

@app.get("/api/security/explain-score")
async def explain_score(authorization: str | None = Header(default=None)):
    require_token(authorization); ss=await security_score(authorization)
    items=[]
    for x in ss.get('leaderboard',[])[:8]:
        if x['risk']>0: items.append({'type':'container-risk','subject':x['container'],'points_lost':round(x['risk']),'detail':'; '.join(x['factors'])})
    for sensor in ss.get('unavailable_sensors',[]): items.append({'type':'sensor-confidence','subject':sensor,'points_lost':{'falco':12,'clamav':10,'crowdsec':9,'trivy':8}.get(sensor,5),'detail':'Core security sensor unavailable'})
    return {'score':ss['score'],'status':ss['status'],'monitoring_confidence':ss['monitoring_confidence'],'contributors':items,'note':'Server score weights the worst active risks; contributor points are explanatory and are not simply summed.'}

@app.put("/api/maintenance/{name}")
async def set_maintenance(name: str, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json(); enabled=bool(d.get('enabled',True)); minutes=max(1,min(int(d.get('minutes',60)),1440)); until=now()+minutes*60 if enabled else None; reason=str(d.get('reason','operator maintenance'))
    with conn() as c: c.execute("INSERT OR REPLACE INTO maintenance(container_name,enabled,until_ts,reason) VALUES(?,?,?,?)",(name,int(enabled),until,reason))
    event('maintenance',name,{'enabled':enabled,'until_ts':until,'reason':reason}); return {'ok':True,'enabled':enabled,'until_ts':until}


def recovery_step(plan_id: int, step: str, status: str, detail: Any = '') -> None:
    if not isinstance(detail,str): detail=json.dumps(detail,default=str,separators=(',',':'))
    with conn() as c: c.execute("INSERT INTO recovery_steps(plan_id,ts,step,status,detail) VALUES(?,?,?,?,?)",(plan_id,now(),step,status,detail[:20000]))
    event('recovery_step',str(plan_id),{'step':step,'status':status,'detail':detail[:500]},'warning' if status in {'failed','blocked'} else 'info')

async def recovery_container_state(name: str) -> dict:
    try:
        obj=await inspect_container(name); state=obj.get('State') or {}; health=(state.get('Health') or {}).get('Status')
        return {'running':bool(state.get('Running')),'status':state.get('Status'),'health':health,'exit_code':state.get('ExitCode')}
    except Exception as e: return {'running':False,'error':str(e)}

@app.post("/api/recovery/plan/{name}")
async def create_recovery_plan(name: str, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json(); policy=default_policy(name)
    hard_protected={'kingdom-manager','kingdom-manager-docker-api','kingdom-manager-recovery-docker-api','kingdom-manager-trivy-docker-api','kingdom-manager-trivy'}
    if name in hard_protected: raise HTTPException(409,'Kingdom core component cannot be rebuilt by automated recovery')
    if policy['protected']: raise HTTPException(409,'Protected container requires policy change before recovery')
    if not policy['allow_rebuild']: raise HTTPException(409,'Approved Rebuild is disabled for this container')
    if risk_profile(name).get('profile')=='database' and not RECOVERY_ALLOW_DATABASES: raise HTTPException(409,'Database recovery is disabled by default. Restore databases manually or explicitly enable KM_RECOVERY_ALLOW_DATABASES after validating backups.')
    obj=await inspect_container(name)
    network_mode=str((obj.get('HostConfig') or {}).get('NetworkMode') or '')
    if network_mode=='host' or network_mode.startswith('container:'): raise HTTPException(409,f'Recovery is not automated for NetworkMode={network_mode}')
    sid=await snapshot(name,'pre-recovery-plan'); incident_id=d.get('incident_id')
    plan={'steps':['capture evidence','isolate','pull known image','remove old container','create quarantine candidate','start candidate','Trivy verification','recreate final container','restore original networks','health observation','close incident'],'image':obj.get('Config',{}).get('Image'),'original_networks':list((obj.get('NetworkSettings',{}).get('Networks') or {}).keys()),'approval_required':True}
    t=now()
    with conn() as c:
        cur=c.execute("INSERT INTO recovery_plans(created_ts,expires_ts,container_name,incident_id,action,status,snapshot_id,plan_json) VALUES(?,?,?,?,?,?,?,?)",(t,t+RECOVERY_APPROVAL_TTL,name,incident_id,'rebuild','pending',sid,json.dumps(plan)))
    return {'plan_id':cur.lastrowid,'expires_ts':t+RECOVERY_APPROVAL_TTL,'plan':plan,'status':'pending-approval'}

async def recovery_docker(method: str,path: str,**kwargs):
    async with httpx.AsyncClient(timeout=120) as client: return await client.request(method,RECOVERY_DOCKER+path,**kwargs)

@app.post("/api/recovery/{plan_id}/approve-and-run")
async def approve_recovery(plan_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: p=c.execute("SELECT * FROM recovery_plans WHERE id=?",(plan_id,)).fetchone()
    if not p: raise HTTPException(404,'Recovery plan not found')
    if p['status']!='pending': raise HTTPException(409,'Recovery plan is not pending')
    if now()>int(p['expires_ts']): raise HTTPException(409,'Recovery approval window expired; create a new plan')
    name=p['container_name']; policy=default_policy(name)
    hard_protected={'kingdom-manager','kingdom-manager-docker-api','kingdom-manager-recovery-docker-api','kingdom-manager-trivy-docker-api','kingdom-manager-trivy'}
    if name in hard_protected or policy['protected'] or not policy['allow_rebuild']: raise HTTPException(409,'Recovery policy does not permit rebuild')
    with conn() as c: snap=c.execute("SELECT inspect_json FROM snapshots WHERE id=?",(p['snapshot_id'],)).fetchone()
    if not snap: raise HTTPException(409,'Recovery snapshot missing')
    obj=json.loads(snap['inspect_json']); image=obj.get('Config',{}).get('Image'); result={'steps':[],'plan_id':plan_id}
    with conn() as c: c.execute("UPDATE recovery_plans SET status='running',approved_ts=? WHERE id=?",(now(),plan_id))
    try:
        recovery_step(plan_id,'evidence','running','Capturing current incident/container evidence')
        if p['incident_id']:
            try: result['evidence']=await capture_incident_evidence(int(p['incident_id']),f"Bearer {API_TOKEN}")
            except Exception as e: result['evidence_warning']=str(e)
        recovery_step(plan_id,'evidence','completed',result.get('evidence',{})); result['steps'].append('evidence-captured')
        recovery_step(plan_id,'isolate','running','Disconnecting original networks and attaching quarantine')
        await isolate(name); recovery_step(plan_id,'isolate','completed'); result['steps'].append('isolated')
        recovery_step(plan_id,'image','running',image); await pull_image(image); recovery_step(plan_id,'image','completed',image); result['steps'].append('image-pulled')
        await recovery_docker('POST',f"/containers/{quote(name,safe='')}/stop?t=20")
        rr=await recovery_docker('DELETE',f"/containers/{quote(name,safe='')}?force=1")
        if rr.status_code not in (204,404): raise RuntimeError('remove failed: '+rr.text[:500])
        result['steps'].append('old-container-removed')
        await ensure_quarantine_network()
        base_cfg=dict(obj.get('Config') or {}); original_hc=dict(obj.get('HostConfig') or {}); original_nets=obj.get('NetworkSettings',{}).get('Networks') or {}
        candidate_cfg=dict(base_cfg); candidate_hc=dict(original_hc); candidate_hc.pop('PortBindings',None); candidate_hc['NetworkMode']=QUARANTINE_NETWORK
        candidate_cfg['HostConfig']=candidate_hc; candidate_cfg['NetworkingConfig']={'EndpointsConfig':{QUARANTINE_NETWORK:{}}}
        recovery_step(plan_id,'candidate','running','Creating replacement in quarantine without published ports')
        cr=await recovery_docker('POST',f"/containers/create?name={quote(name,safe='')}",json=candidate_cfg)
        if cr.status_code!=201: raise RuntimeError('candidate create failed: '+cr.text[:1000])
        sr=await recovery_docker('POST',f"/containers/{quote(name,safe='')}/start")
        if sr.status_code not in (204,304): raise RuntimeError('candidate start failed: '+sr.text[:500])
        await asyncio.sleep(5); cstate=await recovery_container_state(name)
        if not cstate.get('running'): raise RuntimeError('replacement candidate did not stay running: '+json.dumps(cstate))
        recovery_step(plan_id,'candidate','completed',cstate); result['steps'].append('candidate-running')
        recovery_step(plan_id,'trivy','running','Scanning replacement image before restoring service networks')
        tri=await trivy_scan(name); result['trivy']=tri
        if str(tri.get('status','error')).lower() != 'ok':
            recovery_step(plan_id,'trivy','blocked','Trivy verification failed; candidate remains quarantined and service networks will not be restored')
            with conn() as c: c.execute("UPDATE recovery_plans SET status='blocked',executed_ts=?,result=? WHERE id=?",(now(),json.dumps(result,default=str),plan_id))
            return {'ok':False,'blocked':True,'reason':'trivy-scan-error','candidate_quarantined':True,**result}
        if RECOVERY_BLOCK_ON_CRITICAL_CVE and int(tri.get('critical',0) or 0)>0:
            recovery_step(plan_id,'trivy','blocked',f"{tri.get('critical')} critical CVEs found; candidate remains quarantined")
            with conn() as c: c.execute("UPDATE recovery_plans SET status='blocked',executed_ts=?,result=? WHERE id=?",(now(),json.dumps(result,default=str),plan_id))
            return {'ok':False,'blocked':True,'reason':'critical-cves','candidate_quarantined':True,**result}
        recovery_step(plan_id,'trivy','completed',tri); result['steps'].append('trivy-verified')
        await recovery_docker('POST',f"/containers/{quote(name,safe='')}/stop?t=20")
        await recovery_docker('DELETE',f"/containers/{quote(name,safe='')}?force=1")
        final_cfg=dict(base_cfg); final_cfg['HostConfig']=original_hc; final_cfg['NetworkingConfig']={'EndpointsConfig':{k:{'Aliases':v.get('Aliases'),'IPAMConfig':v.get('IPAMConfig')} for k,v in original_nets.items() if k!=QUARANTINE_NETWORK}}
        recovery_step(plan_id,'restore','running','Recreating final container with captured configuration and original networks')
        cr=await recovery_docker('POST',f"/containers/create?name={quote(name,safe='')}",json=final_cfg)
        if cr.status_code!=201: raise RuntimeError('final create failed: '+cr.text[:1000])
        sr=await recovery_docker('POST',f"/containers/{quote(name,safe='')}/start")
        if sr.status_code not in (204,304): raise RuntimeError('final start failed: '+sr.text[:500])
        recovery_step(plan_id,'restore','completed'); result['steps']+=['recreated','original-networks-restored','started']
        recovery_step(plan_id,'observation','running',f'Observing for {RECOVERY_OBSERVATION_SECONDS}s')
        await asyncio.sleep(max(5,RECOVERY_OBSERVATION_SECONDS)); state=await recovery_container_state(name); result['post_recovery_state']=state
        healthy=state.get('running') and state.get('health') not in {'unhealthy'}
        if not healthy:
            try: await isolate(name)
            except Exception: pass
            recovery_step(plan_id,'observation','failed',state)
            raise RuntimeError('post-recovery health observation failed: '+json.dumps(state))
        recovery_step(plan_id,'observation','completed',state); result['steps'].append('health-verified')
        with conn() as c:
            c.execute("UPDATE recovery_plans SET status='completed',executed_ts=?,result=? WHERE id=?",(now(),json.dumps(result,default=str),plan_id))
            if p['incident_id']: c.execute("UPDATE incidents SET status='resolved',updated_ts=?,resolution=? WHERE id=?",(now(),f'Recovered through approved plan #{plan_id}',p['incident_id']))
        event('recovery',name,{'plan_id':plan_id,**result},'warning')
        return {'ok':True,**result}
    except Exception as e:
        result['error']=str(e)
        with conn() as c: c.execute("UPDATE recovery_plans SET status='failed',executed_ts=?,result=? WHERE id=?",(now(),json.dumps(result,default=str),plan_id))
        recovery_step(plan_id,'recovery','failed',str(e)); event('recovery_failed',name,{'plan_id':plan_id,**result},'critical')
        raise HTTPException(500,result)



def audit(action: str, subject: str, outcome: str, detail: Any=None, actor: str='kingdom') -> None:
    with conn() as c:
        c.execute("INSERT INTO audit_log(ts,actor,action,subject,outcome,detail) VALUES(?,?,?,?,?,?)",(now(),actor,action,subject,outcome,json.dumps(detail or {},default=str)[:100000]))

async def _capture_portainer_compose() -> tuple[str|None,str|None]:
    if COMPOSE_SNAPSHOT_PATH:
        try:
            q=Path(COMPOSE_SNAPSHOT_PATH)
            if q.exists() and q.is_file(): return q.read_text(errors='replace')[:500000],f'file:{q}'
        except Exception: pass
    if PORTAINER_URL and PORTAINER_API_KEY and PORTAINER_STACK_ID:
        try:
            async with httpx.AsyncClient(timeout=15,verify=False) as client:
                r=await client.get(f"{PORTAINER_URL}/api/stacks/{PORTAINER_STACK_ID}/file",headers={'X-API-Key':PORTAINER_API_KEY})
                if r.status_code==200:
                    data=r.json(); text=data.get('StackFileContent') if isinstance(data,dict) else None
                    if text: return str(text)[:500000],f'portainer-stack:{PORTAINER_STACK_ID}'
        except Exception as e: event('portainer_snapshot','host',str(e),'warning')
    return None,None

async def capture_config_snapshot(name: str, reason: str) -> dict:
    obj=await inspect_container(name); cfg=obj.get('Config') or {}; nets=(obj.get('NetworkSettings') or {}).get('Networks') or {}
    compose,source=await _capture_portainer_compose()
    with conn() as c:
        cur=c.execute("INSERT INTO config_snapshots(ts,container_name,reason,image_ref,image_id,inspect_json,compose_text,compose_source,env_json,labels_json,networks_json,verified) VALUES(?,?,?,?,?,?,?,?,?,?,?,1)",
          (now(),name,reason,cfg.get('Image'),obj.get('Image'),json.dumps(obj,default=str),compose,source,json.dumps(cfg.get('Env') or []),json.dumps(cfg.get('Labels') or {}),json.dumps(nets,default=str)))
        sid=cur.lastrowid
        # Retention is per container, but never delete snapshots referenced by an active update plan.
        old=c.execute("SELECT id FROM config_snapshots WHERE container_name=? ORDER BY id DESC LIMIT -1 OFFSET ?",(name,max(1,ROLLBACK_RETENTION))).fetchall()
        for r in old: c.execute("DELETE FROM config_snapshots WHERE id=? AND id NOT IN (SELECT COALESCE(snapshot_id,-1) FROM update_plans UNION SELECT COALESCE(rollback_snapshot_id,-1) FROM update_plans)",(r['id'],))
    audit('snapshot',name,'success',{'snapshot_id':sid,'image_id':obj.get('Image'),'compose_source':source})
    return {'snapshot_id':sid,'image_ref':cfg.get('Image'),'image_id':obj.get('Image'),'compose_saved':bool(compose),'compose_source':source}

async def _recreate_from_inspect(name: str, obj: dict, image_override: str|None=None, quarantine: bool=False) -> dict:
    cfg=dict(obj.get('Config') or {}); hc=dict(obj.get('HostConfig') or {}); nets=(obj.get('NetworkSettings') or {}).get('Networks') or {}
    if image_override: cfg['Image']=image_override
    # Docker inspect includes read-only/result fields not accepted by create; Config+HostConfig are the stable recreation source.
    if quarantine:
        await ensure_quarantine_network(); hc.pop('PortBindings',None); hc['NetworkMode']=QUARANTINE_NETWORK; endpoints={QUARANTINE_NETWORK:{}}
    else:
        endpoints={k:{'Aliases':v.get('Aliases'),'IPAMConfig':v.get('IPAMConfig')} for k,v in nets.items() if k!=QUARANTINE_NETWORK}
    cfg['HostConfig']=hc; cfg['NetworkingConfig']={'EndpointsConfig':endpoints}
    await recovery_docker('POST',f"/containers/{quote(name,safe='')}/stop?t=20")
    rr=await recovery_docker('DELETE',f"/containers/{quote(name,safe='')}?force=1")
    if rr.status_code not in (204,404): raise RuntimeError('remove failed: '+rr.text[:500])
    cr=await recovery_docker('POST',f"/containers/create?name={quote(name,safe='')}",json=cfg)
    if cr.status_code!=201: raise RuntimeError('create failed: '+cr.text[:1000])
    sr=await recovery_docker('POST',f"/containers/{quote(name,safe='')}/start")
    if sr.status_code not in (204,304): raise RuntimeError('start failed: '+sr.text[:500])
    await asyncio.sleep(max(5,min(UPDATE_OBSERVATION_SECONDS,30)))
    state=await recovery_container_state(name)
    if not state.get('running') or state.get('health')=='unhealthy': raise RuntimeError('replacement failed health observation: '+json.dumps(state))
    return state

@app.post('/api/updates/{name}/check')
async def update_check(name: str, authorization: str|None=Header(default=None)):
    require_token(authorization); obj=await inspect_container(name); image=(obj.get('Config') or {}).get('Image'); old_id=obj.get('Image')
    if not image: raise HTTPException(409,'Container has no image reference')
    # Capture BEFORE pull so rollback retains immutable old image ID and complete runtime config.
    snap=await capture_config_snapshot(name,'pre-update-check')
    pulled=await pull_image(image); candidate=pulled.get('after')
    status='available' if candidate and candidate!=old_id else 'current'
    with conn() as c:
        cur=c.execute("INSERT INTO update_plans(created_ts,container_name,status,snapshot_id,image_ref,old_image_id,candidate_image_id,result_json,rollback_snapshot_id) VALUES(?,?,?,?,?,?,?,?,?)",
          (now(),name,status,snap['snapshot_id'],image,old_id,candidate,json.dumps({'pull':pulled}),snap['snapshot_id']))
    audit('update-check',name,'success',{'plan_id':cur.lastrowid,'status':status,'old':old_id,'candidate':candidate})
    if status=='available' and DISCORD_NOTIFY_UPDATES:
        await notify('Update available',f'{name}: candidate image detected and rollback snapshot #{snap["snapshot_id"]} captured. Verify in Update Center before applying.','info',force=True)
    return {'plan_id':cur.lastrowid,'status':status,'old_image_id':old_id,'candidate_image_id':candidate,'rollback_snapshot':snap}

@app.post('/api/updates/{plan_id}/verify')
async def update_verify(plan_id: int, authorization: str|None=Header(default=None)):
    require_token(authorization)
    with conn() as c: p=c.execute('SELECT * FROM update_plans WHERE id=?',(plan_id,)).fetchone()
    if not p: raise HTTPException(404,'Update plan not found')
    if p['status']=='current': return {'ok':True,'status':'current','plan_id':plan_id}
    tri=await trivy_scan(p['container_name']) if UPDATE_REQUIRE_TRIVY else {'status':'skipped','critical':0,'high':0}
    blocked=(str(tri.get('status')) not in {'ok','skipped'} or (UPDATE_BLOCK_CRITICAL and int(tri.get('critical',0) or 0)>0) or (UPDATE_BLOCK_HIGH and int(tri.get('high',0) or 0)>0))
    status='blocked' if blocked else 'verified'
    with conn() as c: c.execute('UPDATE update_plans SET status=?,scan_json=? WHERE id=?',(status,json.dumps(tri,default=str),plan_id))
    audit('update-verify',p['container_name'],status,{'plan_id':plan_id,'trivy':tri})
    return {'ok':not blocked,'status':status,'plan_id':plan_id,'trivy':tri}

@app.post('/api/updates/{plan_id}/apply')
async def update_apply(plan_id: int, authorization: str|None=Header(default=None)):
    require_token(authorization)
    with conn() as c: p=c.execute('SELECT * FROM update_plans WHERE id=?',(plan_id,)).fetchone()
    if not p: raise HTTPException(404,'Update plan not found')
    name=p['container_name']; pol=default_policy(name)
    if pol.get('protected'): raise HTTPException(409,'Protected container cannot be auto-updated')
    if risk_profile(name).get('profile') in {'database','security','critical-infrastructure'} and not p['status']=='verified': raise HTTPException(409,'Critical service update must be verified first')
    if p['status'] not in {'verified','available'}: raise HTTPException(409,'Update plan is not ready')
    with conn() as c: snap=c.execute('SELECT * FROM config_snapshots WHERE id=?',(p['snapshot_id'],)).fetchone()
    if not snap: raise HTTPException(409,'Rollback snapshot missing; update refused')
    obj=json.loads(snap['inspect_json']); mounts=obj.get('Mounts') or []
    if mounts and not UPDATE_ALLOW_STATEFUL:
        raise HTTPException(409,'Stateful container has mounts/volumes. Automatic image rollback cannot reverse data migrations; set KM_UPDATE_ALLOW_STATEFUL=true only after validating application-data backups.')
    if mounts and UPDATE_ALLOW_STATEFUL and pol.get('require_backup'):
        with conn() as c: b=c.execute('SELECT verified_ts,provider FROM backup_status WHERE container_name=?',(name,)).fetchone()
        if not b or now()-int(b['verified_ts'])>BACKUP_MAX_AGE_HOURS*3600:
            raise HTTPException(409,f'Stateful update requires a verified data backup newer than {BACKUP_MAX_AGE_HOURS}h. Mark backup status in Disaster Recovery before applying.')
    result={'old_image_id':p['old_image_id'],'candidate_image_id':p['candidate_image_id'],'snapshot_id':p['snapshot_id']}
    try:
        state=await _recreate_from_inspect(name,obj,p['candidate_image_id'],False); result['state']=state
        with conn() as c: c.execute("UPDATE update_plans SET status='completed',approved_ts=?,executed_ts=?,result_json=? WHERE id=?",(now(),now(),json.dumps(result,default=str),plan_id))
        audit('update-apply',name,'success',{'plan_id':plan_id,**result}); event('update',name,{'plan_id':plan_id,'state':'completed'},'info')
        if DISCORD_NOTIFY_UPDATES: await notify('Update completed',f'{name} updated successfully. Rollback snapshot #{p["snapshot_id"]} remains available.','info',force=True)
        return {'ok':True,'plan_id':plan_id,'rollback_available':True,**result}
    except Exception as e:
        result['error']=str(e)
        # Automatic rollback is safer than leaving a failed update in place.
        try:
            rb=await _recreate_from_inspect(name,obj,p['old_image_id'],False); result['automatic_rollback']=rb; status='rolled-back'
        except Exception as re:
            result['rollback_error']=str(re); status='failed'
            try: await isolate(name)
            except Exception: pass
        with conn() as c: c.execute('UPDATE update_plans SET status=?,executed_ts=?,result_json=? WHERE id=?',(status,now(),json.dumps(result,default=str),plan_id))
        audit('update-apply',name,status,{'plan_id':plan_id,**result}); raise HTTPException(500,result)

@app.post('/api/updates/{plan_id}/rollback')
async def update_rollback(plan_id: int, authorization: str|None=Header(default=None)):
    require_token(authorization)
    with conn() as c:
        p=c.execute('SELECT * FROM update_plans WHERE id=?',(plan_id,)).fetchone()
        snap=c.execute('SELECT * FROM config_snapshots WHERE id=(SELECT rollback_snapshot_id FROM update_plans WHERE id=?)',(plan_id,)).fetchone()
    if not p or not snap: raise HTTPException(404,'Rollback plan/snapshot not found')
    obj=json.loads(snap['inspect_json']); state=await _recreate_from_inspect(p['container_name'],obj,p['old_image_id'],False)
    with conn() as c: c.execute("UPDATE update_plans SET status='rolled-back',executed_ts=?,result_json=? WHERE id=?",(now(),json.dumps({'manual_rollback':state},default=str),plan_id))
    audit('rollback',p['container_name'],'success',{'plan_id':plan_id,'snapshot_id':snap['id'],'image_id':p['old_image_id']})
    if DISCORD_NOTIFY_RECOVERY: await notify('Rollback completed',f'{p["container_name"]} restored to immutable image {str(p["old_image_id"])[:24]} from snapshot #{snap["id"]}.','warning',force=True)
    return {'ok':True,'plan_id':plan_id,'restored_image_id':p['old_image_id'],'snapshot_id':snap['id'],'state':state}

@app.get('/api/updates')
async def updates_list(authorization: str|None=Header(default=None)):
    require_token(authorization)
    with conn() as c: return rowdicts(c.execute('SELECT * FROM update_plans ORDER BY id DESC LIMIT 100').fetchall())

@app.get('/api/rollback/{name}')
async def rollback_history(name: str, authorization: str|None=Header(default=None)):
    require_token(authorization)
    with conn() as c: rows=c.execute('SELECT id,ts,reason,image_ref,image_id,compose_source,verified FROM config_snapshots WHERE container_name=? ORDER BY id DESC LIMIT 20',(name,)).fetchall()
    return rowdicts(rows)

@app.get('/api/audit')
async def audit_history(limit: int=100, authorization: str|None=Header(default=None)):
    require_token(authorization)
    with conn() as c: return rowdicts(c.execute('SELECT * FROM audit_log ORDER BY id DESC LIMIT ?',(max(1,min(500,limit)),)).fetchall())

@app.get('/api/security/score/validate')
async def validate_score(authorization: str|None=Header(default=None)):
    require_token(authorization); ss=await security_score(authorization); dims=ss.get('dimensions') or {}
    checks=[]
    def ck(name,ok,detail): checks.append({'check':name,'ok':bool(ok),'detail':detail})
    ck('score-range',0<=ss['score']<=100,ss['score']); ck('dimension-range',all(0<=v<=100 for k,v in dims.items() if isinstance(v,(int,float))),dims)
    ck('sensor-consistency',set(ss.get('unavailable_sensors') or [])=={k for k,v in (ss.get('sensor_health') or {}).items() if v.get('status')!='ok'},ss.get('unavailable_sensors'))
    ck('leaderboard-range',all(0<=x['score']<=100 and 0<=x['risk']<=100 for x in ss.get('leaderboard',[])),'all container scores bounded')
    return {'ok':all(x['ok'] for x in checks),'checks':checks,'risk_model':ss.get('risk_model'),'score':ss['score'],'dimensions':dims}

async def update_engine_loop():
    await asyncio.sleep(max(30,UPDATE_START_DELAY_SECONDS))
    while True:
        try:
            if UPDATE_ENGINE_ENABLED and not global_maintenance_active():
                cs=await list_containers()
                # Rings reduce blast radius; only explicitly opted-in containers are checked automatically.
                eligible=[]
                for x in cs:
                    pol=default_policy(x['name'])
                    if pol.get('auto_update') and not pol.get('protected'): eligible.append((int(pol.get('update_ring') or 2),x['name']))
                for ring,name in sorted(eligible):
                    try:
                        plan=await update_check(name,f'Bearer {API_TOKEN}')
                        if plan.get('status')=='available':
                            ver=await update_verify(int(plan['plan_id']),f'Bearer {API_TOKEN}')
                            if UPDATE_AUTO_APPLY and ver.get('ok') and ring<=2:
                                await update_apply(int(plan['plan_id']),f'Bearer {API_TOKEN}')
                    except Exception as e: event('update_engine',name,str(e),'warning')
        except Exception as e: event('update_engine','host',str(e),'warning')
        await asyncio.sleep(max(3600,UPDATE_CHECK_SECONDS))


def _redacted_config(obj: dict) -> dict:
    cfg=obj.get('Config') or {}; hc=obj.get('HostConfig') or {}; nets=(obj.get('NetworkSettings') or {}).get('Networks') or {}
    env=cfg.get('Env') or []; env_keys=sorted({str(x).split('=',1)[0] for x in env if '=' in str(x)})
    mounts=[]
    for m in obj.get('Mounts') or []:
        mounts.append({'type':m.get('Type'),'source':m.get('Source'),'destination':m.get('Destination'),'rw':m.get('RW')})
    ports=hc.get('PortBindings') or {}
    caps={'add':sorted(hc.get('CapAdd') or []),'drop':sorted(hc.get('CapDrop') or [])}
    return {
      'image':cfg.get('Image'),'env_keys':env_keys,'labels':{str(k):hashlib.sha256(str(v).encode()).hexdigest()[:16] for k,v in (cfg.get('Labels') or {}).items()},'user':cfg.get('User') or '',
      'privileged':bool(hc.get('Privileged')),'network_mode':hc.get('NetworkMode'),'ports':ports,'mounts':sorted(mounts,key=lambda x:(str(x.get('destination')),str(x.get('source')))),
      'networks':sorted(nets.keys()),'caps':caps,'security_opt':sorted(hc.get('SecurityOpt') or []),'read_only_rootfs':bool(hc.get('ReadonlyRootfs')),
      'restart_policy':hc.get('RestartPolicy') or {},'pid_mode':hc.get('PidMode') or '', 'ipc_mode':hc.get('IpcMode') or ''
    }

def _fingerprint(data: dict) -> str:
    return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':'),default=str).encode()).hexdigest()

def _secret_key_findings(obj: dict) -> list[str]:
    keys=[]
    for item in (obj.get('Config') or {}).get('Env') or []:
        k=str(item).split('=',1)[0]
        if any(x in k.lower() for x in ('password','passwd','token','secret','api_key','apikey','private_key','access_key')): keys.append(k)
    return sorted(set(keys))

async def drift_status(name: str) -> dict:
    obj=await inspect_container(name); current=_redacted_config(obj); fp=_fingerprint(current)
    with conn() as c: b=c.execute('SELECT * FROM config_baselines WHERE container_name=?',(name,)).fetchone()
    if not b: return {'container':name,'status':'unbaselined','current_fingerprint':fp,'changes':[],'dangerous':[],'secret_env_keys':_secret_key_findings(obj)}
    old=_safe_json(b['config_json'],{}) or {}; changes=[]
    for k in sorted(set(old)|set(current)):
        if old.get(k)!=current.get(k): changes.append(k)
    dangerous=[]
    if not old.get('privileged') and current.get('privileged'): dangerous.append('privileged enabled')
    if len(current.get('ports') or {})>len(old.get('ports') or {}): dangerous.append('new published port binding')
    old_mounts={str(x.get('source'))+'>'+str(x.get('destination')) for x in old.get('mounts') or []}; new_mounts={str(x.get('source'))+'>'+str(x.get('destination')) for x in current.get('mounts') or []}
    added_mounts=new_mounts-old_mounts
    if any('/var/run/docker.sock' in x for x in added_mounts): dangerous.append('Docker socket mount added')
    if set(current.get('caps',{}).get('add') or [])-set(old.get('caps',{}).get('add') or []): dangerous.append('Linux capabilities added')
    return {'container':name,'status':'drift' if changes else 'clean','baseline_ts':b['ts'],'baseline_fingerprint':b['fingerprint'],'current_fingerprint':fp,'changes':changes,'dangerous':dangerous,'secret_env_keys':_secret_key_findings(obj)}

@app.post('/api/drift/{name}/approve')
async def approve_drift_baseline(name: str, authorization: str|None=Header(default=None)):
    require_token(authorization); obj=await inspect_container(name); data=_redacted_config(obj); fp=_fingerprint(data)
    with conn() as c: c.execute("INSERT OR REPLACE INTO config_baselines(container_name,ts,fingerprint,config_json,actor) VALUES(?,?,?,?,?)",(name,now(),fp,json.dumps(data,sort_keys=True),'operator'))
    audit('drift-baseline',name,'success',{'fingerprint':fp}); return {'ok':True,'container':name,'fingerprint':fp}

@app.get('/api/drift')
async def drift_all(authorization: str|None=Header(default=None)):
    require_token(authorization); out=[]
    for x in await list_containers():
        try: out.append(await drift_status(x['name']))
        except Exception as e: out.append({'container':x['name'],'status':'error','error':str(e)})
    return out

@app.get('/api/drift/{name}')
async def drift_one(name: str, authorization: str|None=Header(default=None)):
    require_token(authorization); return await drift_status(name)

async def dependency_graph_data() -> dict:
    cs=await list_containers(); objs={}
    for x in cs:
        try: objs[x['name']]=await inspect_container(x['name'])
        except Exception: pass
    nodes=[]; edges=[]
    netmap={}; volmap={}
    for name,obj in objs.items():
        cfg=obj.get('Config') or {}; hc=obj.get('HostConfig') or {}; nets=(obj.get('NetworkSettings') or {}).get('Networks') or {}
        nodes.append({'id':name,'image':cfg.get('Image'),'profile':risk_profile(name).get('profile'),'protected':bool(default_policy(name).get('protected'))})
        for n in nets: netmap.setdefault(n,[]).append(name)
        for m in obj.get('Mounts') or []:
            key=str(m.get('Name') or m.get('Source') or '')
            if key: volmap.setdefault(key,[]).append(name)
    def pairs(items,kind,label):
        vals=sorted(set(items))
        for i,a in enumerate(vals):
            for b in vals[i+1:]: edges.append({'source':a,'target':b,'kind':kind,'label':label})
    for n,items in netmap.items():
        if len(items)>1: pairs(items,'network',n)
    for v,items in volmap.items():
        if len(items)>1: pairs(items,'shared-volume',v)
    return {'nodes':nodes,'edges':edges,'networks':{k:sorted(v) for k,v in netmap.items()},'shared_volumes':{k:sorted(v) for k,v in volmap.items() if len(v)>1}}

@app.get('/api/dependencies')
async def dependencies(authorization: str|None=Header(default=None)):
    require_token(authorization); return await dependency_graph_data()

@app.get('/api/disaster-recovery')
async def disaster_recovery(authorization: str|None=Header(default=None)):
    require_token(authorization)
    with conn() as c:
        snaps=rowdicts(c.execute('SELECT id,ts,container_name,reason,image_ref,image_id,compose_source,verified FROM config_snapshots ORDER BY id DESC LIMIT 200').fetchall())
        backups={r['container_name']:dict(r) for r in c.execute('SELECT * FROM backup_status').fetchall()}
    out=[]
    for x in snaps:
        try:
            r=await docker('GET',f"/images/{quote(str(x.get('image_id') or ''),safe='')}/json"); image_present=r.status_code==200
        except Exception: image_present=False
        b=backups.get(x['container_name']); backup_ok=bool(b and now()-int(b['verified_ts'])<=BACKUP_MAX_AGE_HOURS*3600)
        out.append({**x,'image_present':image_present,'compose_saved':bool(x.get('compose_source')),'data_backup_verified':backup_ok,'backup':b})
    return out

@app.post('/api/disaster-recovery/{snapshot_id}/test')
async def test_disaster_recovery(snapshot_id: int, authorization: str|None=Header(default=None)):
    require_token(authorization)
    with conn() as c: r=c.execute('SELECT * FROM config_snapshots WHERE id=?',(snapshot_id,)).fetchone()
    if not r: raise HTTPException(404,'Snapshot not found')
    checks=[]
    try: obj=json.loads(r['inspect_json']); checks.append({'check':'inspect-json','ok':True})
    except Exception as e: return {'ok':False,'checks':[{'check':'inspect-json','ok':False,'detail':str(e)}]}
    ir=await docker('GET',f"/images/{quote(str(r['image_id'] or ''),safe='')}/json"); checks.append({'check':'immutable-image-present','ok':ir.status_code==200,'detail':r['image_id']})
    for net in ((obj.get('NetworkSettings') or {}).get('Networks') or {}):
        nr=await docker('GET',f"/networks/{quote(net,safe='')}"); checks.append({'check':f'network:{net}','ok':nr.status_code==200})
    cfg=_redacted_config(obj); checks.append({'check':'recreate-config-shape','ok':bool(cfg.get('image')),'detail':'configuration can be reconstructed from inspect snapshot'})
    ok=all(x['ok'] for x in checks); audit('rollback-test',r['container_name'],'success' if ok else 'warning',{'snapshot_id':snapshot_id,'checks':checks})
    return {'ok':ok,'snapshot_id':snapshot_id,'container':r['container_name'],'checks':checks,'note':'Dry-run only; no container was changed.'}

@app.put('/api/backups/{name}')
async def set_backup_status(name: str, request: Request, authorization: str|None=Header(default=None)):
    require_token(authorization); d=await request.json(); provider=str(d.get('provider') or 'manual'); detail=str(d.get('detail') or '')[:1000]
    with conn() as c: c.execute('INSERT OR REPLACE INTO backup_status(container_name,verified_ts,provider,detail) VALUES(?,?,?,?)',(name,now(),provider,detail))
    audit('backup-verified',name,'success',{'provider':provider}); return {'ok':True,'container':name,'verified_ts':now(),'provider':provider}

@app.get('/api/backups')
async def backup_status_all(authorization: str|None=Header(default=None)):
    require_token(authorization)
    with conn() as c: rows=rowdicts(c.execute('SELECT * FROM backup_status ORDER BY verified_ts DESC').fetchall())
    for r in rows: r['fresh']=now()-int(r['verified_ts'])<=BACKUP_MAX_AGE_HOURS*3600
    return rows

@app.put('/api/system/maintenance')
async def global_maintenance(request: Request, authorization: str|None=Header(default=None)):
    require_token(authorization); d=await request.json(); enabled=bool(d.get('enabled',True)); minutes=max(1,min(int(d.get('minutes',120)),1440)); value={'enabled':enabled,'until_ts':now()+minutes*60 if enabled else None,'reason':str(d.get('reason') or 'operator maintenance')}
    with conn() as c: c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('global_maintenance',?)",(json.dumps(value),))
    audit('global-maintenance','host','enabled' if enabled else 'disabled',value); return {'ok':True,**value}

@app.get('/api/system/maintenance')
async def global_maintenance_state(authorization: str|None=Header(default=None)):
    require_token(authorization)
    with conn() as c: r=c.execute("SELECT value FROM settings WHERE key='global_maintenance'").fetchone()
    return _safe_json(r[0],{'enabled':False}) if r else {'enabled':False}

@app.post('/api/discord/test')
async def discord_test(authorization: str|None=Header(default=None)):
    require_token(authorization)
    if not DISCORD_WEBHOOK: raise HTTPException(409,'DISCORD_WEBHOOK_URL is not configured')
    return await notify('Discord integration test',f'Kingdom Manager v{VERSION} can deliver security, update, rollback and recovery notifications.','info',force=True)

@app.post('/api/simulate/{scenario}')
async def simulate(scenario: str, authorization: str|None=Header(default=None)):
    require_token(authorization); scenario=scenario.lower()
    cases={
      'falco-only':{'sources':['falco'],'risk':'medium','score':45,'expected':'investigate/baseline; no automatic isolation'},
      'multi-source':{'sources':['falco','crowdsec'],'risk':'high','score':80,'expected':'capture evidence + recommend isolation; destructive action policy-gated'},
      'malware':{'sources':['clamav'],'risk':'high','score':85,'expected':'preserve evidence + quarantine/recovery review'},
      'sensor-outage':{'sources':['clamav-down'],'risk':'monitoring-degraded','score_effect':'Monitoring dimension only','expected':'notify + diagnose; do not claim clean posture'},
      'update-failure':{'sources':['update'],'risk':'operational','expected':'automatic immutable-image/config rollback; isolate if rollback fails'},
    }
    if scenario not in cases: raise HTTPException(400,'scenario must be falco-only, multi-source, malware, sensor-outage, or update-failure')
    return {'simulation':True,'scenario':scenario,'result':cases[scenario],'real_actions_performed':False}

async def system_validation_data() -> dict:
    checks=[]
    def add(name,ok,detail=''): checks.append({'check':name,'ok':bool(ok),'detail':detail})
    try:
        with conn() as c: q=c.execute('PRAGMA quick_check').fetchone()[0]; add('database-integrity',q=='ok',q); sv=c.execute("SELECT value FROM settings WHERE key='schema_version'").fetchone(); add('schema-version',bool(sv and str(sv[0])==str(SCHEMA_VERSION)),str(sv[0]) if sv else 'missing')
    except Exception as e: add('database-integrity',False,str(e))
    try: r=await docker('GET','/_ping'); add('docker-api',r.status_code==200,r.text[:80])
    except Exception as e: add('docker-api',False,str(e))
    try:
        sh=await core_sensor_health()
        for k,v in sh.items(): add('sensor-'+k,v.get('status')=='ok',str(v.get('detail') or v.get('status'))[:180])
    except Exception as e: add('sensors',False,str(e))
    try:
        sc=await security_score(f'Bearer {API_TOKEN}'); add('score-range',0<=int(sc['score'])<=100,str(sc['score'])); add('dimension-range',all(0<=int(v)<=100 for k,v in (sc.get('dimensions') or {}).items() if isinstance(v,(int,float))),str(sc.get('dimensions')))
    except Exception as e: add('scoring',False,str(e))
    try:
        cs=await list_containers(); core=[x['name'] for x in cs if any(q in x['name'].lower() for q in ('kingdom-manager','falco','clamav','trivy','proxy-manager','portainer'))]; unprotected=[x for x in core if not default_policy(x).get('protected')]; add('core-self-protection',not unprotected,','.join(unprotected) or 'all protected')
    except Exception as e: add('core-self-protection',False,str(e))
    add('discord-configured',bool(DISCORD_WEBHOOK),'configured' if DISCORD_WEBHOOK else 'optional: add DISCORD_WEBHOOK_URL')
    add('automatic-destructive-actions-off',not PLAYBOOK_AUTO_ISOLATE and not PLAYBOOK_AUTO_RECOVER,'safe default')
    add('stateful-auto-update-blocked',not UPDATE_ALLOW_STATEFUL,'safe default' if not UPDATE_ALLOW_STATEFUL else 'explicitly enabled')
    ok=all(x['ok'] for x in checks if x['check'] not in {'discord-configured'})
    return {'ok':ok,'version':VERSION,'checks':checks,'passed':sum(1 for x in checks if x['ok']),'total':len(checks)}

@app.get('/api/system/validate')
async def system_validate(authorization: str|None=Header(default=None)):
    require_token(authorization); result=await system_validation_data()
    with conn() as c: c.execute('INSERT INTO validation_runs(ts,status,result_json) VALUES(?,?,?)',(now(),'passed' if result['ok'] else 'failed',json.dumps(result,default=str)))
    return result

@app.get("/api/recovery/plans")
async def recovery_plans(authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: return rowdicts(c.execute("SELECT * FROM recovery_plans ORDER BY id DESC LIMIT 50").fetchall())

@app.get("/api/recovery/plans/{plan_id}")
async def recovery_plan_detail(plan_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c:
        p=c.execute("SELECT * FROM recovery_plans WHERE id=?",(plan_id,)).fetchone(); steps=c.execute("SELECT ts,step,status,detail FROM recovery_steps WHERE plan_id=? ORDER BY id",(plan_id,)).fetchall()
    if not p: raise HTTPException(404,'Recovery plan not found')
    d=dict(p); d['plan']=_safe_json(d.get('plan_json'),{}); d['result_data']=_safe_json(d.get('result'),{}); d['steps']=rowdicts(steps); return d

@app.get("/api/events")
async def events(limit: int = 100, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c:
        return rowdicts(c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall())


@app.get("/api/decisions")
async def decisions(limit: int = 100, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c:
        return rowdicts(c.execute("SELECT * FROM decisions ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall())


@app.get("/api/security/events")
async def security_events(limit: int = 100, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c:
        return rowdicts(c.execute("SELECT id,ts,source,severity,container_name,message FROM security_events ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)).fetchall())


def _safe_json(value: str | None, fallback=None):
    try: return json.loads(value or "")
    except Exception: return fallback


@app.get("/api/activity")
async def activity_feed(limit: int = 50, include_idle: bool = False, kind: str = "", category: str = "", authorization: str | None = Header(default=None)):
    require_token(authorization)
    q="SELECT id,ts,kind,subject,detail,severity FROM events"; args=[]; where=[]
    if not include_idle: where.append("kind!='idle'")
    if kind: where.append("kind=?"); args.append(kind)
    category_map={
        'security':['security','security_event','suppression'],
        'scans':['trivy','trivy_auto_scan','trivy_auto_complete','trivy_auto_error','incident_scan'],
        'incidents':['incident','incident_status','incident_isolated','investigation','evidence','playbook'],
        'recovery':['recovery','recovery_failed','snapshot'],
        'system':['monitor_error','maintenance','update_check','container','policy','risk_profile','trivy_scheduler'],
    }
    kinds=category_map.get(category.lower()) if category else None
    if kinds:
        where.append("kind IN ("+','.join('?' for _ in kinds)+")"); args.extend(kinds)
    if where: q+=" WHERE "+" AND ".join(where)
    q+=" ORDER BY id DESC LIMIT ?"; args.append(max(1,min(limit,200)))
    with conn() as c: rows=c.execute(q,args).fetchall()
    icon_map={'security':'🛡','security_event':'🛡','trivy':'🔎','trivy_auto_scan':'🔎','trivy_auto_complete':'✅','trivy_auto_error':'⚠️','idle':'💤','recovery':'♻️','recovery_failed':'🚨','evidence':'🧾','snapshot':'📸','maintenance':'🛠','suppression':'🔕','update_check':'⬆️','monitor_error':'⚠️','trivy_scheduler':'🔎','incident_status':'🚨','incident_scan':'🔎','incident_isolated':'🚨','investigation':'🧠','playbook':'🧭'}
    out=[]
    for r in rows:
        d=dict(r); detail=d.get('detail') or ''; parsed=_safe_json(detail)
        if isinstance(parsed,dict):
            if d['kind']=='idle': summary=f"Idle-ready · CPU {parsed.get('cpu','?')}%"
            elif d['kind']=='trivy_auto_complete': summary=f"Scan complete · {parsed.get('critical',0)} critical · {parsed.get('high',0)} high"
            elif d['kind']=='recovery': summary=str(parsed.get('action') or 'Recovery action completed')
            else: summary=', '.join(f"{k}: {v}" for k,v in list(parsed.items())[:3])
        else: summary=detail
        out.append({**d,'icon':icon_map.get(d['kind'],'•'),'summary':str(summary)[:220]})
    return out


@app.get("/api/containers/{name}/security-profile")
async def container_security_profile(name: str, authorization: str | None = Header(default=None)):
    require_token(authorization); obj=await inspect_container(name); policy=default_policy(name); rp=risk_profile(name); ss=await security_score(authorization); riskrow=next((x for x in ss.get('leaderboard',[]) if x['container']==name),None)
    with conn() as c:
        sec=rowdicts(c.execute("SELECT id,ts,source,severity,message,raw_json FROM security_events WHERE container_name=? ORDER BY id DESC LIMIT 20",(name,)).fetchall())
        scan_attempt=c.execute("SELECT id,ts,image,status,critical,high,medium,result_json FROM scans WHERE container_name=? ORDER BY id DESC LIMIT 1",(name,)).fetchone()
        scan_success=c.execute("SELECT id,ts,image,status,critical,high,medium,result_json FROM scans WHERE container_name=? AND status='ok' ORDER BY id DESC LIMIT 1",(name,)).fetchone()
        inc=rowdicts(c.execute("SELECT id,created_ts,updated_ts,severity,status,title,summary,score FROM incidents WHERE container_name=? ORDER BY id DESC LIMIT 10",(name,)).fetchall()); maint=c.execute("SELECT enabled,until_ts,reason FROM maintenance WHERE container_name=?",(name,)).fetchone()
    for e in sec:
        raw=_safe_json(e.pop('raw_json',None),{}) or {}; e['rule']=(raw.get('rule') or falco_rule_from_message(e.get('message',''))) if e.get('source')=='falco' else ''
        sup=active_suppression(e.get('source',''),name,e.get('message',''),e.get('rule',''))
        e['expected']=bool(sup); e['suppression']=sup
    def scan_view(row):
        if not row: return None
        d=dict(row); raw=_safe_json(d.pop('result_json',None),{}) or {}
        if d.get('status')!='ok': d['error']=str(raw.get('error') or raw.get('raw') or 'Trivy scan failed')[-1200:]
        return d
    mounts=[{'type':m.get('Type'),'source':m.get('Source'),'destination':m.get('Destination'),'rw':m.get('RW')} for m in (obj.get('Mounts') or [])]
    return {'container':name,'image':obj.get('Config',{}).get('Image'),'image_id':obj.get('Image'),'state':obj.get('State',{}),'networks':list((obj.get('NetworkSettings',{}).get('Networks') or {}).keys()),'mounts':mounts,'policy':policy,'risk_profile':rp,'risk':riskrow,'recent_security_events':sec,'latest_scan_attempt':scan_view(scan_attempt),'last_successful_scan':scan_view(scan_success),'latest_scan':scan_view(scan_success),'incidents':inc,'maintenance':dict(maint) if maint else {'enabled':0}}


@app.post("/api/incidents/{incident_id}/status")
async def set_incident_status(incident_id: int, request: Request, authorization: str | None = Header(default=None)):
    require_token(authorization); d=await request.json(); status=str(d.get('status','investigating')).lower()
    if status not in {'open','investigating','isolated','resolved','dismissed'}: raise HTTPException(400,'Invalid incident status')
    with conn() as c:
        r=c.execute("SELECT container_name FROM incidents WHERE id=?",(incident_id,)).fetchone()
        if not r: raise HTTPException(404,'Incident not found')
        c.execute("UPDATE incidents SET status=?,updated_ts=? WHERE id=?",(status,now(),incident_id))
    event('incident_status',r['container_name'] or 'host',{'incident_id':incident_id,'status':status}); return {'ok':True,'incident_id':incident_id,'status':status}


@app.get("/api/security/history")
async def security_history(hours: int = 168, authorization: str | None = Header(default=None)):
    require_token(authorization); cutoff=now()-max(1,min(hours,24*90))*3600
    with conn() as c: return rowdicts(c.execute("SELECT ts,score,status,overall_risk,monitoring_confidence,critical,high,medium,low FROM score_history WHERE ts>? ORDER BY ts",(cutoff,)).fetchall())



@app.get("/api/intelligence/status")
async def intelligence_status(authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c:
        subjects=c.execute("SELECT DISTINCT container_name FROM security_events WHERE source='falco' AND container_name IS NOT NULL AND ts>?",(now()-7*86400,)).fetchall()
    stable=learning=novel=0; examples=[]
    for r in subjects:
        name=r['container_name']
        with conn() as c:
            top=c.execute("SELECT message,raw_json,count(*) n,min(ts) first_ts,max(ts) last_ts FROM security_events WHERE source='falco' AND container_name=? AND ts>? GROUP BY message ORDER BY n DESC LIMIT 1",(name,now()-7*86400)).fetchone()
        if not top: continue
        raw=_safe_json(top['raw_json'],{}) or {}; rule=str(raw.get('rule') or falco_rule_from_message(top['message']) or 'Other Falco rule')
        b=falco_baseline_metrics(name,rule,7)
        if b['status']=='stable': stable+=1
        elif b['status']=='learning': learning+=1
        else: novel+=1
        if len(examples)<8: examples.append({'container':name,**b})
    return {'stable':stable,'learning':learning,'novel':novel,'subjects':stable+learning+novel,'examples':examples,'auto_suppression':False,'note':'Adaptive baselines are advisory and never auto-suppress Falco rules.'}

@app.get("/api/intelligence/baselines")
async def baseline_suggestions(days: int = 7, authorization: str | None = Header(default=None)):
    require_token(authorization); cutoff=now()-max(1,days)*86400
    with conn() as c:
        rows=c.execute("SELECT container_name,message,raw_json,severity,ts FROM security_events WHERE source='falco' AND container_name IS NOT NULL AND ts>? ORDER BY ts",(cutoff,)).fetchall()
    groups={}
    for r in rows:
        raw=_safe_json(r['raw_json'],{}) or {}; rule=str(raw.get('rule') or falco_rule_from_message(r['message']) or 'Other Falco rule')
        key=(r['container_name'],rule); g=groups.setdefault(key,{'container':r['container_name'],'rule':rule,'count':0,'first_ts':int(r['ts']),'last_ts':int(r['ts']),'max_severity':str(r['severity'])})
        g['count']+=1; g['first_ts']=min(g['first_ts'],int(r['ts'])); g['last_ts']=max(g['last_ts'],int(r['ts']))
    out=[]
    for (name,rule),g in groups.items():
        b=falco_baseline_metrics(name,rule,days)
        scan=latest_scan_context(name, successful_only=True)
        clean=bool(scan and not int(scan.get('critical') or 0) and not int(scan.get('high') or 0) and not int(scan.get('medium') or 0))
        approved=active_suppression('falco',name,rule=rule)
        learned_adjustment=b['score_adjustment'] if clean else 0
        approved_adjustment=(-KNOWN_GOOD_MAX_ATTENUATION if approved else 0)
        g.update(b); g.update({'suggested':b['status']=='stable' and not approved,'approved':bool(approved),'suppression':approved,'auto_applied':False,'clean_trivy':clean,'effective_score_adjustment':approved_adjustment if approved else learned_adjustment})
        out.append(g)
    out.sort(key=lambda x:(x['status']!='stable',-x['count']))
    return out[:100]


@app.get("/api/incidents/{incident_id}/assessment-history")
async def assessment_history(incident_id: int, authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: rows=c.execute("SELECT ts,classification,confidence,summary,score_snapshot,details_json FROM incident_assessments WHERE incident_id=? ORDER BY id DESC LIMIT 50",(incident_id,)).fetchall()
    out=[]
    for r in rows:
        d=dict(r); d['details']=_safe_json(d.pop('details_json') or '{}',{}) or {}; out.append(d)
    return out

@app.get("/api/recommendations")
async def recommendations(authorization: str | None = Header(default=None)):
    require_token(authorization); t=now(); ss=await security_score(authorization); cs=await list_containers(False); rec=[]
    for sensor in ss.get('unavailable_sensors',[]): rec.append({'priority':'critical','title':f'{sensor.title()} sensor unavailable','detail':'Monitoring coverage is degraded. Diagnose the engine before trusting a clean score.','action':'diagnose'})
    with conn() as c:
        for item in cs:
            name=item['name']
            if name.startswith('kingdom-manager'): continue
            attempt=c.execute("SELECT ts,critical,high,status FROM scans WHERE container_name=? ORDER BY id DESC LIMIT 1",(name,)).fetchone()
            success=c.execute("SELECT ts,critical,high,status FROM scans WHERE container_name=? AND status='ok' ORDER BY id DESC LIMIT 1",(name,)).fetchone()
            if attempt and attempt['status']!='ok': rec.append({'priority':'medium','title':f'Retry Trivy scan for {name}','detail':'The latest Trivy attempt failed. Kingdom will not treat 0/0/0 from an errored attempt as clean evidence.','action':'scan','container':name})
            elif not success: rec.append({'priority':'medium','title':f'Scan {name}','detail':'No successful Trivy result exists for this running container yet.','action':'scan','container':name})
            elif int(success['critical'] or 0)>0: rec.append({'priority':'high','title':f'Critical CVEs in {name}','detail':f"{success['critical']} critical and {success['high']} high findings. Review fixes/update image.",'action':'review-cves','container':name})
        noisy=c.execute("SELECT container_name,count(*) n FROM security_events WHERE source='falco' AND ts>? GROUP BY container_name HAVING n>=100 ORDER BY n DESC LIMIT 5",(t-86400,)).fetchall()
        for n in noisy: rec.append({'priority':'low','title':f'Tune Falco noise for {n["container_name"] or "host"}','detail':f'{n["n"]} Falco events in 24h. Review known-good suppressions rather than ignoring globally.','action':'review-falco','container':n['container_name']})
        opens=c.execute("SELECT id,container_name,severity,status,title FROM incidents WHERE status NOT IN ('resolved','dismissed') ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 ELSE 2 END,updated_ts DESC").fetchall()
        for i in opens[:5]: rec.append({'priority':i['severity'],'title':f'Review incident #{i["id"]}','detail':i['title'],'action':'incident','incident_id':i['id'],'container':i['container_name']})
    order={'critical':0,'high':1,'medium':2,'low':3,'info':4}; rec.sort(key=lambda x:order.get(x.get('priority','info'),4)); return rec[:20]


async def build_report(days: int) -> dict:
    start=now()-days*86400; cs=await list_containers(); ss=await security_score(f"Bearer {API_TOKEN}")
    with conn() as c:
        sec=c.execute("SELECT severity,count(*) n FROM security_events WHERE ts>? GROUP BY severity",(start,)).fetchall(); acts=c.execute("SELECT kind,count(*) n FROM events WHERE ts>? GROUP BY kind",(start,)).fetchall(); scans=c.execute("SELECT count(*) n,coalesce(sum(critical),0) critical,coalesce(sum(high),0) high,coalesce(sum(medium),0) medium FROM scans WHERE ts>? AND status='ok'",(start,)).fetchone(); scan_errors=c.execute("SELECT count(*) n FROM scans WHERE ts>? AND status!='ok'",(start,)).fetchone()['n']; incidents=c.execute("SELECT severity,count(*) n FROM incidents WHERE created_ts>? GROUP BY severity",(start,)).fetchall(); resolved=c.execute("SELECT count(*) n FROM incidents WHERE updated_ts>? AND status='resolved'",(start,)).fetchone()['n']; hist=c.execute("SELECT score FROM score_history WHERE ts>? ORDER BY ts LIMIT 1",(start,)).fetchone()
    return {'period_days':days,'generated_at':now(),'score':ss['score'],'score_change':ss['score']-(hist['score'] if hist else ss['score']),'monitoring_confidence':ss['monitoring_confidence'],'containers':{'total':len(cs),'running':sum(x['state']=='running' for x in cs)},'security':{r['severity']:r['n'] for r in sec},'activity':{r['kind']:r['n'] for r in acts},'trivy':{**dict(scans),'errors':scan_errors},'incidents':{r['severity']:r['n'] for r in incidents},'resolved_incidents':resolved,'recommendations':(await recommendations(f"Bearer {API_TOKEN}"))[:8]}


@app.get("/api/reports/daily")
async def daily_report(authorization: str | None = Header(default=None)):
    require_token(authorization); return await build_report(1)


@app.get("/api/reports/history")
async def report_history(authorization: str | None = Header(default=None)):
    require_token(authorization)
    with conn() as c: return rowdicts(c.execute("SELECT id,ts,report_type,delivered_discord,delivered_n8n FROM report_history ORDER BY id DESC LIMIT 30").fetchall())


@app.post("/api/reports/send/{kind}")
async def send_report(kind: str, authorization: str | None = Header(default=None)):
    require_token(authorization); days=1 if kind=='daily' else 7 if kind=='weekly' else 0
    if not days: raise HTTPException(400,'kind must be daily or weekly')
    report=await build_report(days); body=f"Security score: {report['score']}/100 ({report['score_change']:+d})\nContainers: {report['containers']['running']}/{report['containers']['total']} running\nTrivy: {report['trivy']['n']} scans, {report['trivy']['critical']} critical, {report['trivy']['high']} high\nIncidents: {sum(report['incidents'].values())} opened, {report['resolved_incidents']} resolved"
    delivery=await notify(f"Kingdom {kind} security report",body,'info',force=True)
    with conn() as c: c.execute("INSERT INTO report_history(ts,report_type,payload,delivered_discord,delivered_n8n) VALUES(?,?,?,?,?)",(now(),kind,json.dumps(report,default=str),int(str(delivery['discord']).startswith('http-2')),int(str(delivery['n8n']).startswith('http-2'))))
    return {'ok':True,'report':report,'delivery':delivery}


@app.get("/api/reports/weekly")
async def weekly_report(authorization: str | None = Header(default=None)):
    require_token(authorization)
    return await build_report(7)


async def monitor_loop():
    await asyncio.sleep(max(0, MONITOR_SCHEDULER_OFFSET_SECONDS))
    while True:
        try:
            if global_maintenance_active():
                await asyncio.sleep(max(60, CHECK_SECONDS)); continue
            cs = await list_containers()
            for c in cs:
                if c["name"] in {"kingdom-manager", "kingdom-manager-docker-api", TRIVY_RUNNER}:
                    continue
                p = default_policy(c["name"])
                if c["state"] == "running":
                    stats = await sample_stats(c["name"])
                    idle, idle_since = update_idle(c["name"], stats, p)
                    # We record idle readiness; auto-update still requires an explicit update check/pull.
                    if idle:
                        event("idle", c["name"], {"cpu": stats["cpu"], "idle_since": idle_since})
                elif p["auto_restart"] and not p["protected"]:
                    status = (c.get("status") or "").lower()
                    # Restart only unexpected failures, not clean/manual exits.
                    if "exited (0)" not in status and "created" not in status:
                        r = await docker("POST", f"/containers/{quote(c['name'], safe='')}/start")
                        if r.status_code in (204, 304):
                            event("recovery", c["name"], "auto-started after unexpected stop", "warning")
                            await notify("Container recovered", f"{c['name']} was automatically started after an unexpected stop.", "warning")
        except Exception as e:
            event("monitor_error", "host", str(e), "warning")
        await asyncio.sleep(max(60, CHECK_SECONDS))


async def trivy_auto_loop():
    """Low-impact vulnerability coverage with visible scheduler state.

    Scans at most one running container per interval. Scheduler state/errors are
    persisted in settings so the dashboard can explain why scan count is zero.
    """
    await asyncio.sleep(max(10, TRIVY_AUTO_SCAN_START_DELAY_SECONDS, TRIVY_SCHEDULER_OFFSET_SECONDS))
    with conn() as db:
        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state','starting') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    event("trivy_scheduler", "host", {"state":"started", "interval":TRIVY_AUTO_SCAN_EVERY_SECONDS}, "info")
    while True:
        target = None
        try:
            if not TRIVY_AUTO_SCAN_ENABLED:
                with conn() as db:
                    db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state','disabled') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
            else:
                cs = [c for c in await list_containers(False) if c.get("state") == "running"]
                excluded = {"kingdom-manager", "kingdom-manager-docker-api", "kingdom-manager-trivy", "kingdom-manager-trivy-docker-api"}
                candidates=[]
                with conn() as db:
                    for c in cs:
                        name=c["name"]
                        if name in excluded:
                            continue
                        last=db.execute("SELECT ts,status FROM scans WHERE container_name=? ORDER BY id DESC LIMIT 1", (name,)).fetchone()
                        last_ts=int(last["ts"]) if last else 0
                        if last_ts == 0 or now()-last_ts >= TRIVY_RESCAN_SECONDS:
                            candidates.append((last_ts,name))
                if candidates:
                    candidates.sort(key=lambda x:(x[0],x[1]))
                    _, target=candidates[0]
                    with conn() as db:
                        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (f"scanning:{target}",))
                        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_last_attempt',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now()),))
                    event("trivy_auto_scan", target, "scheduled low-impact vulnerability scan", "info")
                    result=await trivy_scan(target)
                    with conn() as db:
                        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state','idle') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
                        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_last_success',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (str(now()),))
                        db.execute("DELETE FROM settings WHERE key='trivy_scheduler_last_error'")
                    event("trivy_auto_complete", target, {"critical":result.get("critical",0),"high":result.get("high",0),"medium":result.get("medium",0)}, "info")
                else:
                    with conn() as db:
                        db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state','coverage-current') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        except Exception as e:
            msg=str(e)[:2000]
            with conn() as db:
                db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_state','error') ON CONFLICT(key) DO UPDATE SET value=excluded.value")
                db.execute("INSERT INTO settings(key,value) VALUES('trivy_scheduler_last_error',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", (msg,))
            event("trivy_auto_error", target or "host", msg, "warning")
        await asyncio.sleep(max(300, TRIVY_AUTO_SCAN_EVERY_SECONDS))


async def sensor_watch_loop():
    await asyncio.sleep(max(0, SENSOR_SCHEDULER_OFFSET_SECONDS))
    while True:
        try:
            health=await core_sensor_health()
            with conn() as c:
                for sensor,data in health.items():
                    key=f'sensor_watch_{sensor}'; prev=c.execute('SELECT value FROM settings WHERE key=?',(key,)).fetchone(); previous=prev[0] if prev else 'unknown'; current=str(data.get('status') or 'unknown')
                    if current!=previous:
                        c.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)',(key,current))
                        if previous!='unknown':
                            if current!='ok' and DISCORD_NOTIFY_SENSOR_FAILURES:
                                asyncio.create_task(notify(f'{sensor.upper()} sensor degraded',f"Status changed {previous} → {current}. Detail: {str(data.get('detail') or '')[:800]}",'high',force=True))
                            elif current=='ok' and DISCORD_NOTIFY_SENSOR_FAILURES:
                                asyncio.create_task(notify(f'{sensor.upper()} sensor recovered',f'Status changed {previous} → OK. Monitoring coverage restored.','info',force=True))
        except Exception as e: event('sensor_watch','host',str(e),'warning')
        await asyncio.sleep(60)

async def drift_scan_loop():
    await asyncio.sleep(max(0, DRIFT_SCHEDULER_OFFSET_SECONDS))
    while True:
        if DRIFT_SCAN_ENABLED:
            try:
                for x in await list_containers():
                    d=await drift_status(x['name'])
                    if d.get('status')=='drift' and d.get('dangerous'):
                        event('config_drift',x['name'],{'changes':d.get('changes'),'dangerous':d.get('dangerous')},'high')
                        await notify('Dangerous configuration drift',f"{x['name']}: {', '.join(d.get('dangerous') or [])}",'high')
            except Exception as e: event('drift_error','host',str(e),'warning')
        await asyncio.sleep(max(300,DRIFT_SCAN_SECONDS))

async def score_history_loop():
    await asyncio.sleep(max(0, SCORE_SCHEDULER_OFFSET_SECONDS))
    while True:
        try:
            ss=await security_score(f"Bearer {API_TOKEN}"); sc=ss.get('severity_counts') or {}
            with conn() as c:
                c.execute("INSERT INTO score_history(ts,score,status,overall_risk,monitoring_confidence,critical,high,medium,low) VALUES(?,?,?,?,?,?,?,?,?)",(now(),ss['score'],ss['status'],ss['overall_risk'],ss['monitoring_confidence'],sc.get('critical',0),sc.get('high',0),sc.get('medium',0),sc.get('low',0))); c.execute("DELETE FROM score_history WHERE ts<?",(now()-90*86400,))
        except Exception as e: event('score_history_error','host',str(e),'warning')
        await asyncio.sleep(max(300,SCORE_HISTORY_INTERVAL_SECONDS))


async def reporting_loop():
    await asyncio.sleep(90)
    while True:
        try:
            local=datetime.now(TZ); daykey=local.strftime('%Y-%m-%d'); weekkey=f"{local.isocalendar().year}-{local.isocalendar().week}"
            with conn() as c:
                daily=c.execute("SELECT value FROM settings WHERE key='daily_sent'").fetchone(); weekly=c.execute("SELECT value FROM settings WHERE key='weekly_sent'").fetchone()
            if DAILY_REPORT_ENABLED and local.hour>=DAILY_REPORT_HOUR and (not daily or daily[0]!=daykey):
                report=await build_report(1); body=f"Score {report['score']}/100 ({report['score_change']:+d}) · {report['containers']['running']}/{report['containers']['total']} containers running · {sum(report['incidents'].values())} incidents · {report['trivy']['critical']} critical CVEs"; delivery=await notify('Kingdom daily security report',body,'info',force=True)
                with conn() as c:
                    c.execute("INSERT INTO report_history(ts,report_type,payload,delivered_discord,delivered_n8n) VALUES(?,?,?,?,?)",(now(),'daily',json.dumps(report,default=str),int(str(delivery['discord']).startswith('http-2')),int(str(delivery['n8n']).startswith('http-2')))); c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('daily_sent',?)",(daykey,))
            if local.weekday()==WEEKLY_REPORT_WEEKDAY and local.hour>=WEEKLY_REPORT_HOUR and (not weekly or weekly[0]!=weekkey):
                report=await build_report(7); body=f"Score {report['score']}/100 ({report['score_change']:+d}) · {report['containers']['running']}/{report['containers']['total']} containers running · {sum(report['incidents'].values())} incidents · {report['trivy']['critical']} critical CVEs"; delivery=await notify('Kingdom weekly security report',body,'info',force=True)
                with conn() as c:
                    c.execute("INSERT INTO report_history(ts,report_type,payload,delivered_discord,delivered_n8n) VALUES(?,?,?,?,?)",(now(),'weekly',json.dumps(report,default=str),int(str(delivery['discord']).startswith('http-2')),int(str(delivery['n8n']).startswith('http-2')))); c.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('weekly_sent',?)",(weekkey,))
        except Exception as e: event('reporting_error','report',str(e),'warning')
        await asyncio.sleep(1800)


async def inventory_cache_loop():
    await asyncio.sleep(2)
    while True:
        try:
            await list_containers(False, fresh=True)
            # Full inventory changes less often and is used by lifecycle/reporting views.
            if int(time.monotonic()) % 60 < 15:
                await list_containers(True, fresh=True)
        except Exception as e:
            event("inventory_cache_error","host",str(e)[:500],"warning")
        await asyncio.sleep(max(8.0, DOCKER_CACHE_TTL_SECONDS))


async def dashboard_snapshot_loop():
    """Keep the primary dashboard score warm without coupling unlock to live dependencies."""
    await asyncio.sleep(5)
    while True:
        try:
            await security_score(f"Bearer {API_TOKEN}")
        except Exception as e:
            event("dashboard_snapshot_error","host",str(e)[:500],"warning")
        await asyncio.sleep(max(10.0, DASHBOARD_REFRESH_SECONDS))

@app.on_event("startup")
async def startup():
    asyncio.create_task(inventory_cache_loop()); asyncio.create_task(dashboard_snapshot_loop()); asyncio.create_task(monitor_loop()); asyncio.create_task(trivy_auto_loop()); asyncio.create_task(score_history_loop()); asyncio.create_task(reporting_loop()); asyncio.create_task(update_engine_loop()); asyncio.create_task(drift_scan_loop()); asyncio.create_task(sensor_watch_loop())

@app.on_event("shutdown")
async def shutdown():
    global _docker_client
    if _docker_client is not None:
        await _docker_client.aclose(); _docker_client=None


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(DASHBOARD)


DASHBOARD = r'''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Kingdom Manager</title>
<style>
:root{--bg:#050b12;--panel:#09131d;--line:#1c3040;--text:#eef5fa;--muted:#8fa3b5;--gold:#d8a844;--green:#4ee07d;--lime:#92e65c;--amber:#ffb02e;--red:#ff5f57;--blue:#32b7ff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 50% -20%,#10283b 0,#07111b 30%,var(--bg) 68%);color:var(--text);font:14px Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;min-height:100vh}.wrap{max-width:1560px;margin:auto;padding:26px}.top{display:flex;align-items:center;justify-content:space-between;gap:18px}.brand{display:flex;align-items:center;gap:14px}.crest{width:54px;height:62px;border:2px solid var(--gold);clip-path:polygon(50% 0,96% 16%,88% 72%,50% 100%,12% 72%,4% 16%);display:grid;place-items:center;color:var(--gold);font-size:28px;background:#0b1620}.brand h1{font-size:25px;letter-spacing:.04em;margin:0}.muted,.tiny{color:var(--muted)}.tiny{font-size:12px}.system{display:flex;align-items:center;gap:12px}.okdot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 12px var(--green)}button,input,select{background:#0b1722;color:var(--text);border:1px solid #294153;border-radius:9px;padding:8px 11px}button{cursor:pointer}.hero{margin-top:22px;border:1px solid var(--line);border-radius:14px;background:linear-gradient(115deg,#08131d,#07111a 60%,#0a1721);padding:22px;display:grid;grid-template-columns:1.2fr .75fr .72fr;gap:24px;box-shadow:0 22px 70px #0007}.scorebox{display:flex;align-items:center;gap:28px}.ring{--score:82;--mood:#4ee07d;width:180px;height:180px;border-radius:50%;background:conic-gradient(var(--mood) calc(var(--score)*1%),#18303a 0);padding:10px}.ringin{width:100%;height:100%;border-radius:50%;background:#07111a;display:grid;place-items:center;text-align:center;border:1px solid #213745}.score{font-size:58px;font-weight:800;line-height:.9}.status{font-size:34px;font-weight:800}.facewrap{display:grid;place-items:center}.facehalo{width:205px;height:205px;border-radius:50%;border:2px solid var(--gold);display:grid;place-items:center}.face{width:154px;height:154px;border-radius:50%;position:relative;transition:.35s;background:radial-gradient(circle at 36% 28%,#a8ffc1,#5ee58a 36%,#289c50 75%,#12612d)}.eye{position:absolute;top:52px;width:17px;height:24px;border-radius:50%;background:#06120d}.eye.l{left:42px}.eye.r{right:42px}.mouth{position:absolute;left:50%;top:92px;width:62px;height:30px;transform:translateX(-50%);border-bottom:6px solid #06120d;border-radius:0 0 60px 60px}.face.good{background:radial-gradient(circle at 36% 28%,#d5ff9d,#92e65c 38%,#559d34 76%,#275d20)}.face.elevated{background:radial-gradient(circle at 36% 28%,#fff1a8,#ffd24d 40%,#b4771d 76%,#6d4213)}.face.elevated .mouth{height:5px;border-radius:0;top:105px}.face.high,.face.critical{background:radial-gradient(circle at 36% 28%,#ffe09b,#ffad3f 45%,#a84420)}.face.critical{background:radial-gradient(circle at 36% 28%,#ffb3a9,#ff6158 45%,#8b1f27)}.face.high .mouth,.face.critical .mouth{border-bottom:0;border-top:6px solid #06120d;border-radius:60px 60px 0 0;top:106px}.severity{border-left:1px solid var(--line);padding-left:22px}.sevrow{display:flex;justify-content:space-between;padding:14px 4px;border-bottom:1px solid #152b39;font-weight:700}.attention{border:1px solid #274050;border-radius:12px;padding:18px;background:#08141e}.attention-ok{text-align:center;padding:18px 4px;color:var(--green)}.check{font-size:40px}.engines{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:14px}.card{background:linear-gradient(145deg,#09141e,#07111a);border:1px solid var(--line);border-radius:13px;padding:18px}.engine-head{display:flex;justify-content:space-between;align-items:center;font-weight:800;font-size:16px}.tag{font-size:11px;border:1px solid #294153;border-radius:999px;padding:4px 8px}.good{color:var(--green)}.bad{color:var(--red)}.warn{color:var(--amber)}.engine-kpi{font-size:28px;margin-top:18px}.spark{height:24px;margin-top:12px;border-bottom:1px solid #183042;background:linear-gradient(175deg,transparent 55%,#32b7ff 56%,transparent 59%)}.grid2{display:grid;grid-template-columns:1.15fr .85fr;gap:14px;margin-top:14px}.grid3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-top:14px}.table{width:100%;border-collapse:collapse}.table th{text-align:left;color:var(--muted);font-size:11px;padding:10px;border-bottom:1px solid var(--line)}.table td{padding:11px 10px;border-bottom:1px solid #142634}.table tr.clickable{cursor:pointer}.table tr.clickable:hover{background:#0d1c28}.state{font-weight:700}.activity{max-height:390px;overflow:auto}.event{padding:11px;border-bottom:1px solid #142634;display:flex;justify-content:space-between;gap:12px}.event strong{display:block}.event-actions{display:flex;gap:5px;flex-wrap:wrap;margin-top:6px}.event-actions button{font-size:11px;padding:5px 7px}.footer{display:flex;justify-content:space-between;gap:12px;margin:18px 0;color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px}.containers{margin-top:14px}.container-row{display:flex;justify-content:space-between;gap:12px;padding:12px 4px;border-bottom:1px solid #142634}.toolbar,.policybar{display:flex;gap:6px;flex-wrap:wrap}.policybar{margin-top:8px}.policybtn{font-size:11px;padding:5px 8px;border-radius:999px}.policybtn.on{border-color:#3b8d59;color:var(--green);background:#0b2117}.policybtn.off{color:var(--muted)}.policybtn.protected.on{border-color:#d8a844;color:var(--gold);background:#201806}button{min-height:36px;font-weight:650;transition:border-color .15s,background .15s,transform .08s,opacity .15s}button:hover:not(:disabled){border-color:#44647a;background:#102131}button:active:not(:disabled){transform:translateY(1px)}button:disabled{opacity:.48;cursor:not-allowed}.toolbar button,.event-actions button{min-height:34px}.btn-primary{background:#12334a;border-color:#2b79a4;color:#dff5ff}.btn-success{background:#0d291a;border-color:#367b50;color:var(--green)}.btn-secondary{background:#0b1722;border-color:#294153}.danger{border-color:#69323a;background:#211015;color:#ffb7b2}.action-busy{position:relative;pointer-events:none;opacity:.62}.action-busy:after{content:'…';margin-left:6px}.loginbox button{width:100%;margin-top:2px}.login-status{min-height:18px;margin-top:10px}.stale-banner{border:1px solid #6b5627;background:#211b0b;color:#ffd66a;border-radius:9px;padding:8px 10px;margin:10px 0}.login{position:fixed;inset:0;background:#04090ef2;display:flex;align-items:center;justify-content:center;z-index:30}.loginbox{width:min(440px,92vw);background:#09141e;border:1px solid #294153;border-radius:16px;padding:26px}.loginbox input{width:100%;margin:12px 0}.hidden{display:none!important}.section-title{font-size:16px;letter-spacing:.03em;margin:0 0 12px}.sev-critical{color:var(--red)}.sev-high{color:var(--amber)}.sev-medium{color:#ffd95a}.sev-low{color:var(--green)}.recommend{border-left:3px solid var(--blue);padding-left:10px}.recommend.high,.recommend.critical{border-left-color:var(--red)}.recommend.medium{border-left-color:var(--amber)}.chart{width:100%;height:110px}.drawer{position:fixed;inset:0 0 0 auto;width:min(620px,96vw);background:#07111a;border-left:1px solid #294153;z-index:25;box-shadow:-25px 0 80px #000b;padding:22px;overflow:auto}.drawer-head{display:flex;justify-content:space-between;align-items:center;position:sticky;top:-22px;background:#07111a;padding:18px 0;z-index:2}.drawer section{border-top:1px solid var(--line);padding:14px 0}.kv{display:grid;grid-template-columns:150px 1fr;gap:8px;padding:5px 0}.toastbox{position:fixed;right:24px;bottom:24px;z-index:60;display:grid;gap:10px;max-width:min(420px,calc(100vw - 32px))}.toast{background:#0b1722;border:1px solid #294153;border-left:4px solid var(--green);border-radius:10px;padding:12px 14px;box-shadow:0 14px 45px #0009;color:var(--text)}.toast.error{border-left-color:var(--red)}.toast.warn{border-left-color:var(--amber)}.filterbar{display:flex;gap:6px;flex-wrap:wrap;margin:-2px 0 10px}.filterbar button.active{border-color:var(--blue);color:var(--blue);background:#092033}.falco-sample{margin:8px 0 0;padding:9px;border:1px solid #173243;border-radius:8px;background:#071723}.modalback{position:fixed;inset:0;background:#02070cc9;z-index:80;display:grid;place-items:center;padding:20px}.modalbox{width:min(520px,94vw);background:#09141e;border:1px solid #294153;border-radius:14px;padding:20px;box-shadow:0 25px 90px #000c}.modalbox h3{margin:0 0 8px}.modalbox input{width:100%;margin:12px 0}.modal-actions{display:flex;justify-content:flex-end;gap:8px;margin-top:12px}
/* v3.1.3 warm-start + unified action system */
:root{--btn-h:38px;--btn-radius:10px;--btn-border:#274255;--btn-bg:#0b1823;--btn-bg-hover:#102638;--btn-blue:#1887d8;--btn-blue-hover:#2097eb;--btn-green:#14713c;--btn-green-hover:#19894a;--btn-red:#96343a;--btn-red-hover:#b13d44;--chip-bg:#0c1a25}
button{appearance:none;height:var(--btn-h);min-height:var(--btn-h);display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:0 14px;border:1px solid var(--btn-border);border-radius:var(--btn-radius);background:var(--btn-bg);color:#edf6fb;font-size:13px;font-weight:700;line-height:1;white-space:nowrap;box-shadow:0 1px 0 #ffffff08 inset,0 1px 2px #0005;transition:background .14s,border-color .14s,color .14s,transform .08s,box-shadow .14s}
button:hover:not(:disabled){background:var(--btn-bg-hover);border-color:#3e647c;box-shadow:0 0 0 1px #2c587233 inset,0 4px 14px #0005}
button:focus-visible{outline:2px solid #2ca9ff;outline-offset:2px}
button:active:not(:disabled){transform:translateY(1px)}
button:disabled{opacity:.46;cursor:not-allowed;filter:saturate(.5)}
.btn-primary{background:linear-gradient(180deg,#1685d4,#106eb5);border-color:#249ee9;color:#fff}.btn-primary:hover:not(:disabled){background:linear-gradient(180deg,var(--btn-blue-hover),#1279c8);border-color:#45b6ff}
.btn-secondary{background:#0d1b27;border-color:#29495f;color:#e7f1f7}.btn-secondary:hover:not(:disabled){background:#112637}
.btn-success{background:linear-gradient(180deg,#176f3d,#115b32);border-color:#279456;color:#effff5}.btn-success:hover:not(:disabled){background:linear-gradient(180deg,var(--btn-green-hover),#116737);border-color:#39ad68}
.danger,.btn-danger{background:#241217;border-color:#743039;color:#ffc8c5}.danger:hover:not(:disabled),.btn-danger:hover:not(:disabled){background:#35171d;border-color:#a53d46;color:#fff}
.btn-ghost{background:transparent;border-color:#263e4f;color:#a9bfd0}.btn-ghost:hover:not(:disabled){background:#0b1721;color:#e8f4fb}
.btn-compact{height:32px;min-height:32px;padding:0 11px;font-size:12px;border-radius:9px}
.actionbar,.event-actions,.toolbar,.modal-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.event-actions{margin-top:10px}
.event-actions button{height:36px;min-height:36px;padding:0 12px;font-size:12px}
.incident-item{padding:16px 14px;border:1px solid transparent;border-bottom:1px solid #142b3a;border-radius:10px;display:grid;grid-template-columns:1fr auto;gap:14px;transition:background .14s,border-color .14s}
.incident-item:hover{background:#0a1823;border-color:#17384d}
.incident-main{min-width:0}.incident-title{display:flex;align-items:center;gap:8px;flex-wrap:wrap}.incident-title strong{font-size:15px}.incident-meta{margin-top:5px;color:#8ea7b9;font-size:12px}.incident-state{align-self:start;min-width:82px;text-align:center}
.nav-actions{display:flex;gap:8px;flex-wrap:wrap}.nav-actions button{height:36px;min-height:36px;padding:0 14px;background:#0b1823}.nav-actions button:hover{border-color:#3b6986}
.status-chip,.tag{display:inline-flex;align-items:center;justify-content:center;min-height:27px;padding:0 9px;border-radius:999px;border:1px solid #29475a;background:var(--chip-bg);font-size:11px;font-weight:800;letter-spacing:.01em;white-space:nowrap}.tag.good,.status-chip.good{border-color:#1c6940;background:#0b2117;color:#50ea82}.tag.warn,.status-chip.warn{border-color:#76561f;background:#241c09;color:#ffc241}.tag.bad,.status-chip.bad{border-color:#71323a;background:#241116;color:#ff6962}
.baseline-item{display:grid;grid-template-columns:1fr auto;gap:16px;padding:18px 14px;border:1px solid #162f40;border-radius:12px;background:#081722;margin:10px 0}.baseline-item:hover{border-color:#244a62;background:#0a1b28}.baseline-title{font-size:14px;font-weight:800;line-height:1.35}.baseline-meta{color:#8ea7b9;font-size:12px;line-height:1.55;margin:5px 0 11px}.baseline-actions{display:flex;gap:8px;flex-wrap:wrap}.baseline-side{display:flex;align-items:flex-start}.drawer{width:min(700px,96vw);padding:22px 24px}.drawer-head{border-bottom:1px solid #142b39;margin:0 -2px 8px;padding:18px 2px 16px}.drawer-head h2{margin:0;font-size:22px}.drawer-head button{height:38px;min-height:38px}
.container-row .toolbar{justify-content:flex-end}.container-row .toolbar button{height:34px;min-height:34px;padding:0 11px;font-size:12px}.policybtn{height:28px!important;min-height:28px!important;padding:0 9px!important;border-radius:999px!important;font-size:11px!important;font-weight:700!important}
.action-busy{pointer-events:none;opacity:.72}.action-busy:before{content:'';width:12px;height:12px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:kmspin .7s linear infinite}.action-busy:after{content:none}@keyframes kmspin{to{transform:rotate(360deg)}}
@media(max-width:720px){.incident-item{grid-template-columns:1fr}.incident-state{justify-self:start}.event-actions button{flex:1 1 auto}.nav-actions button{flex:1 1 calc(50% - 8px)}.baseline-item{grid-template-columns:1fr}.baseline-side{justify-content:flex-start}.drawer{padding:16px}}
@media(max-width:1050px){.hero{grid-template-columns:1fr}.severity{border-left:0;padding-left:0}.engines{grid-template-columns:repeat(2,1fr)}.grid2,.grid3{grid-template-columns:1fr}}@media(max-width:650px){.wrap{padding:14px}.scorebox{flex-direction:column;align-items:flex-start}.engines{grid-template-columns:1fr}.system{display:none}}
</style></head><body>
<div id="toastbox" class="toastbox"></div>
<div id="kmModal" class="modalback hidden"><div class="modalbox"><h3 id="kmModalTitle">Kingdom Manager</h3><div id="kmModalText" class="muted"></div><input id="kmModalInput" class="hidden"><div class="modal-actions"><button id="kmModalCancel">Cancel</button><button id="kmModalOk">Continue</button></div></div></div>
<div id="login" class="login"><div class="loginbox"><div class="brand"><div class="crest">♛</div><div><h1>ENTER THE KINGDOM</h1><div class="muted">Kingdom Manager secure console</div></div></div><input id="token" type="password" placeholder="Kingdom Manager token"><button class="btn-primary" onclick="saveToken(event.currentTarget)">Unlock Dashboard</button><p id="loginerr" class="bad"></p></div></div>
<div id="drawer" class="drawer hidden"><div class="drawer-head"><div><h2 id="drawerTitle">Container</h2><div id="drawerSubtitle" class="muted"></div></div><button class="btn-secondary" onclick="closeDrawer()">Close</button></div><div id="drawerBody"></div></div>
<div class="wrap"><div class="top"><div class="brand"><div class="crest">♛</div><div><h1>KINGDOM MANAGER</h1><div class="muted">Security Overview · Intelligence · Incident Response · Controlled Recovery · Reports</div></div></div><div class="system"><span class="okdot"></span><div><b id="systemState" class="good">Checking systems</b><div id="lastCheck" class="tiny">—</div></div><button onclick="logout()">Lock</button></div></div>
<section class="hero"><div><h2 class="section-title">KINGDOM SECURITY SCORE</h2><div class="scorebox"><div id="scoreRing" class="ring"><div class="ringin"><div><div id="score" class="score">—</div><div class="muted">/100</div></div></div></div><div><div id="scoreStatus" class="status">CHECKING</div><h3>Overall Risk: <span id="overallRisk">—</span></h3><p id="scoreText" class="muted">Evaluating independent security engines and container risk.</p><div class="tiny"><span id="suppressed">0</span> known-good signals suppressed in 24h · Monitoring confidence <button style="padding:2px 7px;font-size:11px" onclick="openConfidence()"><span id="confidence">—</span>%</button></div><div id="dimensions" class="tiny" style="margin-top:10px;line-height:1.8">Threat — · Vulnerability — · Exposure — · Monitoring — · Trust —</div></div></div></div><div class="facewrap"><div class="facehalo"><div id="moodFace" class="face"><span class="eye l"></span><span class="eye r"></span><span class="mouth"></span></div></div><div class="tiny" style="margin-top:12px">KINGDOM SENTINEL</div></div><div class="severity"><div class="sevrow sev-critical"><span>⬡ CRITICAL</span><span id="sevCritical">0</span></div><div class="sevrow sev-high"><span>⬡ HIGH</span><span id="sevHigh">0</span></div><div class="sevrow sev-medium"><span>⬡ MEDIUM</span><span id="sevMedium">0</span></div><div class="sevrow sev-low"><span>⬡ LOW</span><span id="sevLow">0</span></div><div id="attention" class="attention" style="margin-top:16px"></div></div></section>
<div id="engines" class="engines"></div>
<div class="grid2"><div class="card"><div style="display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;margin-bottom:12px"><h2 class="section-title" style="margin:0">🚨 INCIDENT CENTER</h2><div class="nav-actions"><button class="btn-compact" onclick="openBaselines()">Baselines</button><button class="btn-compact" onclick="openTrustDiagnostics()">Trust</button><button class="btn-compact" onclick="openIncidentHistory()">History</button><button class="btn-compact" onclick="openUpdates()">Updates</button><button class="btn-compact" onclick="openRecoveryCenter()">Recovery</button><button class="btn-compact" onclick="openDrift()">Drift</button><button class="btn-compact" onclick="openDependencies()">Map</button><button class="btn-compact" onclick="openValidation()">Validate</button></div></div><div id="incidents" class="activity"></div></div><div class="card"><h2 class="section-title">🧠 EXPLAIN MY SCORE</h2><div id="scoreExplain" class="activity"></div></div></div>
<div class="grid2"><div class="card"><h2 class="section-title">CONTAINER RISK LEADERBOARD</h2><table class="table"><thead><tr><th>CONTAINER</th><th>SCORE</th><th>STATE</th><th>PROFILE</th><th>TOP RISK FACTOR</th></tr></thead><tbody id="leaderboard"></tbody></table></div><div class="card"><h2 class="section-title">RECENT KINGDOM ACTIVITY</h2><div id="activityFilters" class="filterbar"><button class="active" onclick="setActivityFilter('',this)">All</button><button onclick="setActivityFilter('security',this)">Security</button><button onclick="setActivityFilter('scans',this)">Scans</button><button onclick="setActivityFilter('incidents',this)">Incidents</button><button onclick="setActivityFilter('recovery',this)">Recovery</button><button onclick="setActivityFilter('system',this)">System</button></div><div id="activity" class="activity"></div></div></div>
<div class="grid3"><div class="card"><h2 class="section-title">📈 SCORE HISTORY · 7 DAYS</h2><svg id="historyChart" class="chart" viewBox="0 0 500 110" preserveAspectRatio="none"></svg><div id="historyMeta" class="tiny"></div></div><div class="card"><h2 class="section-title">💡 SECURITY RECOMMENDATIONS</h2><div id="recommendations" class="activity"></div></div><div class="card"><h2 class="section-title">📋 REPORTING & NOTIFICATIONS</h2><div id="reporting"></div><div class="toolbar" style="margin-top:12px"><button onclick="sendReport('daily')">Send Daily</button><button onclick="sendReport('weekly')">Send Weekly</button><button onclick="testDiscord()">Test Discord</button></div></div></div>
<div class="card containers"><h2 class="section-title">CONTAINER LIFE & CONTROLS</h2><div id="containers"></div></div><div class="footer"><span>🧠 Decision Engine <b class="good">Active</b></span><span>🛡 Versioned DB migrations</span><span id="footerEval">Last evaluation —</span><span>v3.1.3 LTS · Warm Start + Staggered Schedulers + Recovery ♛</span></div></div>
<script>
let TOKEN=localStorage.getItem('km_token')||'',ACTIVITY_FILTER='',RECS=[];const API_GETS=new Map(),ACTIONS=new Set();function hdr(){return {'Authorization':'Bearer '+TOKEN,'Content-Type':'application/json'}}async function _api(url,opt={}){let ctrl=new AbortController(),timeout=Number(opt.timeout||20000),timer=setTimeout(()=>ctrl.abort(),timeout);delete opt.timeout;opt.headers={...(opt.headers||{}),...hdr()};opt.signal=opt.signal||ctrl.signal;try{let r=await fetch(url,opt);let type=(r.headers.get('content-type')||'').toLowerCase(),text=await r.text();if(r.status===401){document.getElementById('login').classList.remove('hidden');throw Error('Invalid or expired Kingdom Manager token')}if(!type.includes('application/json')){throw Error(`Kingdom API returned ${r.status} ${r.statusText||''} instead of JSON. The proxy or backend may be temporarily unavailable.`)}let d={};try{d=text?JSON.parse(text):{}}catch{throw Error(`Kingdom API returned malformed JSON (${r.status})`)}if(!r.ok)throw Error(typeof d.detail==='string'?d.detail:(d.detail?JSON.stringify(d.detail):`Request failed (${r.status})`));return d}catch(e){if(e.name==='AbortError')throw Error(`Kingdom request timed out after ${Math.round(timeout/1000)}s: ${url}`);throw e}finally{clearTimeout(timer)}}async function api(url,opt={}){let method=(opt.method||'GET').toUpperCase();if(method==='GET'){let key=url;if(API_GETS.has(key))return API_GETS.get(key);let p=_api(url,opt).finally(()=>API_GETS.delete(key));API_GETS.set(key,p);return p}return _api(url,opt)}async function guarded(key,label,fn){if(ACTIONS.has(key)){toast(`${label} is already running`,'warn');return null}ACTIONS.add(key);let btn=(typeof event!=='undefined'&&event?.currentTarget instanceof HTMLElement)?event.currentTarget:null,old=btn?.textContent;if(btn){btn.disabled=true;btn.classList.add('action-busy');btn.textContent=label+'…'}try{return await fn()}finally{ACTIONS.delete(key);if(btn){btn.disabled=false;btn.classList.remove('action-busy');btn.textContent=old}}}async function saveToken(btn=null){let err=document.getElementById('loginerr');TOKEN=document.getElementById('token').value.trim();err.textContent='';if(!TOKEN){err.textContent='Enter the Kingdom Manager token';return}if(btn){btn.disabled=true;btn.textContent='Verifying…'}try{let verified=false,lastErr=null;for(let attempt=0;attempt<2&&!verified;attempt++){try{await _api('/api/auth/verify',{timeout:15000});verified=true}catch(e){lastErr=e;if(attempt===0&&(/timed out|502|503|504|temporarily unavailable/i.test(e.message))){err.textContent='Kingdom is waking up — retrying connection…';await new Promise(r=>setTimeout(r,750));continue}throw e}}if(!verified)throw lastErr||Error('Unable to verify Kingdom token');localStorage.setItem('km_token',TOKEN);document.getElementById('login').classList.add('hidden');toast('Kingdom unlocked','ok');try{let boot=await _api('/api/dashboard/bootstrap',{timeout:3000});if(boot?.score)renderWarmScore(boot.score,boot.saved_ts)}catch{}load().catch(e=>toast(e.message,'error'))}catch(e){localStorage.removeItem('km_token');err.textContent=e.message}finally{if(btn){btn.disabled=false;btn.textContent='Unlock Dashboard'}}}function logout(){localStorage.removeItem('km_token');TOKEN='';document.getElementById('login').classList.remove('hidden')}function esc(s){return String(s??'').replace(/[&<>"']/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]))}function age(sec){if(sec==null)return'never';if(sec<60)return sec+'s ago';if(sec<3600)return Math.floor(sec/60)+'m ago';return Math.floor(sec/3600)+'h ago'}function toast(msg,tone='ok'){let box=document.getElementById('toastbox'),el=document.createElement('div');el.className='toast '+(tone==='error'?'error':tone==='warn'?'warn':'');el.textContent=msg;box.appendChild(el);setTimeout(()=>el.remove(),5000)}function kmDialog({title='Kingdom Manager',text='',input=false,value='',ok='Continue',danger=false}){return new Promise(resolve=>{let m=document.getElementById('kmModal'),i=document.getElementById('kmModalInput'),b=document.getElementById('kmModalOk'),c=document.getElementById('kmModalCancel');document.getElementById('kmModalTitle').textContent=title;document.getElementById('kmModalText').textContent=text;i.classList.toggle('hidden',!input);i.value=value;b.textContent=ok;b.classList.toggle('danger',danger);m.classList.remove('hidden');if(input)setTimeout(()=>i.focus(),30);let done=v=>{m.classList.add('hidden');b.onclick=c.onclick=null;resolve(v)};b.onclick=()=>done(input?i.value:true);c.onclick=()=>done(input?null:false)})}function renderWarmScore(ss,savedTs=0){if(!ss||ss.score==null)return;let color=ss.score>=90?'#4ee07d':ss.score>=75?'#92e65c':ss.score>=55?'#ffd24d':ss.score>=35?'#ff9f35':'#ff5f57',ring=document.getElementById('scoreRing');ring.style.setProperty('--score',ss.score);ring.style.setProperty('--mood',color);document.getElementById('score').textContent=ss.score;document.getElementById('scoreStatus').textContent=(ss.status||'LAST VERIFIED')+' · REFRESHING';document.getElementById('scoreStatus').style.color=color;document.getElementById('overallRisk').textContent=ss.overall_risk||'—';document.getElementById('confidence').textContent=ss.monitoring_confidence??'—';document.getElementById('suppressed').textContent=ss.suppressed_24h||0;let dm=ss.dimensions||{};document.getElementById('dimensions').textContent=`Threat ${dm.threat??'—'} · Vulnerability ${dm.vulnerability??'—'} · Exposure ${dm.exposure??'—'} · Monitoring ${dm.monitoring??'—'} · Trust ${dm.trust??'—'}`;document.getElementById('scoreText').textContent='Showing last verified Kingdom state while live intelligence refreshes.';document.getElementById('lastCheck').textContent=savedTs?'Last verified: '+age(Math.max(0,Math.floor(Date.now()/1000-savedTs))):'Refreshing live state…';let sc=ss.severity_counts||{};['Critical','High','Medium','Low'].forEach(k=>document.getElementById('sev'+k).textContent=sc[k.toLowerCase()]||0)}async function act(n,a){if((a==='stop'||a==='isolate')&&!(await kmDialog({title:`${a.toUpperCase()} ${n}?`,text:'This changes the running state or network exposure of the container.',ok:a.toUpperCase(),danger:true})))return;return guarded('container:'+n+':'+a,a[0].toUpperCase()+a.slice(1),async()=>{try{let url=a==='isolate'?`/api/containers/${encodeURIComponent(n)}/isolate`:`/api/containers/${encodeURIComponent(n)}/action/${a}`;await api(url,{method:'POST'});toast(`${a} completed for ${n}`);await load()}catch(e){toast(e.message,'error');throw e}})}async function scan(n){return guarded('scan:'+n,'Scanning',async()=>{try{let d=await api(`/api/containers/${encodeURIComponent(n)}/trivy`,{method:'POST',timeout:780000});toast(`Trivy ${n}: ${d.critical||0} critical · ${d.high||0} high · ${d.medium||0} medium`);await load();if(!document.getElementById('drawer').classList.contains('hidden'))await openDrawer(n);return d}catch(e){toast(e.message,'error');throw e}})}async function scanIncident(id,n){return guarded('incident-scan:'+id,'Scanning',async()=>{try{toast(`Trivy scan started for ${n}`,'warn');let d=await api(`/api/incidents/${id}/scan`,{method:'POST',timeout:780000}),sc=d.scan||{},a=d.assessment||{};toast(`Trivy ${n}: ${sc.critical||0} critical · ${sc.high||0} high · ${sc.medium||0} medium · assessment ${a.confidence||'?'}%`);await load();await openIncident(id);return d}catch(e){toast(e.message,'error');throw e}})}async function upd(n){try{let d=await api(`/api/containers/${encodeURIComponent(n)}/check-update`,{method:'POST'});toast(d.update_available?'New image pulled; container was not recreated automatically.':'No image ID change detected.');load()}catch(e){toast(e.message,'error')}}async function policy(n,key,value){return guarded('policy:'+n+':'+key,'Saving',async()=>{try{await api(`/api/policies/${encodeURIComponent(n)}`,{method:'PUT',body:JSON.stringify({[key]:value})});await load();if(!document.getElementById('drawer').classList.contains('hidden'))await openDrawer(n)}catch(e){toast(e.message,'error');throw e}})}function policyButton(n,label,key,on,extra=''){return `<button class="policybtn ${on?'on':'off'} ${extra}" onclick="event.stopPropagation();policy('${esc(n)}','${key}',${on?'false':'true'})">${on?'✓':'○'} ${label}</button>`}function engineCard(name,icon,status,body){let cls=status==='ok'?'good':status==='down'||status==='error'?'bad':'warn';return `<div class="card"><div class="engine-head"><span>${icon} ${name.toUpperCase()}</span><span class="tag ${cls}">${esc(status||'ready').toUpperCase()}</span></div>${body}<div class="spark"></div></div>`}
async function incidentStatus(id,status,refresh=true){await api(`/api/incidents/${id}/status`,{method:'POST',body:JSON.stringify({status})});if(refresh)await load()}async function createRecovery(n,incidentId){try{let p=await api(`/api/recovery/plan/${encodeURIComponent(n)}`,{method:'POST',body:JSON.stringify({incident_id:incidentId})});let yes=await kmDialog({title:`Approve recovery plan #${p.plan_id}?`,text:`${n}: capture evidence → isolate → quarantine replacement → Trivy verification → recreate → health observation.`,ok:'Approve & Run',danger:true});if(!yes)return;let r=await api(`/api/recovery/${p.plan_id}/approve-and-run`,{method:'POST'});toast(r.ok?'Recovery completed successfully.':`Recovery stopped safely: ${r.reason||'review required'}`,r.ok?'ok':'warn');load();if(incidentId)openIncident(incidentId);else openDrawer(n)}catch(e){toast(e.message,'error')}}async function markIncidentExpected(id,rule,n){let p=await api('/api/suppressions/preview',{method:'POST',body:JSON.stringify({source:'falco',container_name:n,rule_contains:rule})});let preview=`NARROW SCOPE ONLY\n${p.scope}\n\nMatches in last 24h: ${p.matching_events_24h}\nCurrent container risk context: ${p.estimated_current_risk_points} points\n\nThis will NOT suppress the rule globally.`;let ok=await kmDialog({title:'Suppression impact preview',text:preview,ok:'Continue'});if(!ok)return;let expiry=await kmDialog({title:'Suppression duration',text:'Enter hours. Examples: 24 = 1 day, 168 = 7 days, 0 = permanent.',input:true,value:'168',ok:'Continue'});if(expiry===null)return;let reason=await kmDialog({title:'Reason for known-good behavior',text:`Scope: ${p.scope}`,input:true,value:'Known-good behavior for this container',ok:'Save suppression'});if(!reason)return;await api(`/api/incidents/${id}/mark-expected`,{method:'POST',body:JSON.stringify({rule,reason,expires_hours:Number(expiry)||0})});toast(`Known-good scope saved for ${n}: ${rule}`);closeDrawer();load()}async function runSafePlaybook(id){return guarded('playbook:'+id,'Running playbook',async()=>{try{toast('Running safe Kingdom playbook steps…','warn');let r=await api(`/api/incidents/${id}/playbook/run-safe`,{method:'POST',timeout:900000});toast(r.ok?'Safe playbook completed':'Playbook completed with warnings',r.ok?'ok':'warn');await load();await openIncident(id);return r}catch(e){toast(e.message,'error');throw e}})}async function isolateIncident(id){if(!(await kmDialog({title:'Isolate incident container?',text:'Kingdom Manager will remove the container from its current service networks and place it in quarantine.',ok:'Isolate',danger:true})))return;try{await api(`/api/incidents/${id}/isolate`,{method:'POST'});toast('Incident container isolated','warn');openIncident(id);load()}catch(e){toast(e.message,'error')}}async function openIncident(id){try{await incidentStatus(id,'investigating',false);let [inc,a,pb]=await Promise.all([api(`/api/incidents/${id}`),api(`/api/incidents/${id}/investigation`),api(`/api/incidents/${id}/playbook`)]);let n=inc.container_name||'',cls=a.classification||'unverified',tone=cls==='high-confidence-threat'?'bad':cls==='suspicious'?'warn':cls==='likely-expected'?'good':'';document.getElementById('drawerTitle').textContent=`Incident #${id} · ${n||'host'}`;document.getElementById('drawerSubtitle').textContent=`${inc.severity.toUpperCase()} · ${inc.status} · Kingdom assessment ${a.confidence}%`;let rules=(a.falco_rules||[]).map(x=>{let samples=(x.samples||[]).filter(z=>z.proc_exe||z.process||z.cmdline||z.image||z.user||z.fd).map(z=>`<div class="falco-sample tiny"><b>Observed</b>${z.proc_exe?` · exe ${esc(z.proc_exe)}`:''}${z.process?` · process ${esc(z.process)}`:''}${z.parent?` · parent ${esc(z.parent)}`:''}${z.user?` · user ${esc(z.user)}`:''}${z.image?`<br>image ${esc(z.image)}`:''}${z.cmdline?`<br>cmd ${esc(z.cmdline).slice(0,180)}`:''}${z.fd?`<br>fd ${esc(z.fd).slice(0,180)}`:''}</div>`).join('');return `<div class="event"><div><strong>${esc(x.rule)}</strong><span class="tiny">${x.count} matching events · first ${new Date(x.first_ts*1000).toLocaleString()} · last ${new Date(x.last_ts*1000).toLocaleString()}</span>${samples}</div><span class="tag ${x.severity==='critical'?'bad':'warn'}">${esc(x.severity)}</span></div>`}).join('')||'<div class="tiny">No Falco rules in the last 24h.</div>';let factors=(a.factors||[]).map(x=>`<div class="tiny" style="padding:5px 0">• ${esc(x)}</div>`).join('');let math=(a.confidence_math||[]).map(x=>`<div class="event"><span class="tiny">${esc(x.reason)}</span><b class="${x.points>=0?'good':'warn'}">${x.points>=0?'+':''}${x.points}%</b></div>`).join('')||'<div class="tiny">No confidence adjustments recorded.</div>';let scan=a.latest_scan?`Last successful · ${a.latest_scan.critical} critical · ${a.latest_scan.high} high · ${a.latest_scan.medium} medium · ${age(Math.max(0,Math.floor(Date.now()/1000)-a.latest_scan.ts))}`:'No successful scan';if(a.latest_scan_attempt&&a.latest_scan_attempt.status!=='ok')scan+=`<br><span class=\"bad\">Latest attempt: SCAN ERROR</span>`;let allow=!!a.recovery_available,top=a.top_rule||'',expected=!!a.expected_rule,recovery=(a.recovery_reasons||[]).map(x=>`<div class="tiny warn">• ${esc(x)}</div>`).join('');document.getElementById('drawerBody').innerHTML=`<section><h3>🧭 RESPONSE PLAYBOOK</h3><div class="tiny">${esc(pb.name||'Kingdom adaptive response')} · safe automation ${pb.enabled?'enabled':'disabled'}</div>${(pb.steps||[]).map((x,i)=>`<div class="event"><div><strong>${i+1}. ${esc(x.title)}</strong><span class="tiny">gate: ${esc(x.gate)}${x.auto_eligible?' · auto-eligible':''}${x.destructive?' · destructive':''}</span></div><span class="tag ${x.destructive?'bad':x.auto_eligible?'good':'warn'}">${x.destructive?'APPROVAL':x.auto_eligible?'SAFE AUTO':x.gate.toUpperCase()}</span></div>`).join('')}<div class="toolbar" style="margin-top:10px"><button class="btn-primary" onclick="runSafePlaybook(${id})">Run Safe Steps</button>${allow?`<button class="danger" onclick="createRecovery('${esc(n)}',${id})">Prepare Approved Recovery</button>`:''}</div></section><section><h3>KINGDOM INTELLIGENCE</h3><p>${esc(a.intelligence_summary||a.summary)}</p><div class="kv"><b>Suggested action</b><span>${esc((a.recommended_action||'continue-investigation').replaceAll('-',' '))}</span></div></section><section><h3>KINGDOM ASSESSMENT</h3><div class="kv"><b>Classification</b><span class="${tone}">${esc(cls).replaceAll('-',' ').toUpperCase()}</span></div><div class="kv"><b>Confidence</b><span>${a.confidence}% ${a.confidence_delta?`(${a.confidence_delta>0?'+':''}${a.confidence_delta} since last assessment)`:''}</span></div><div class="kv"><b>Server score delta</b><span>${a.score_delta>0?'+':''}${a.score_delta||0}</span></div><p class="muted">${esc(a.summary)}</p>${factors}<h4>WHY THIS CONFIDENCE?</h4>${math}</section><section><h3>CORROBORATION</h3><div class="kv"><b>Falco match scope</b><span>${a.matching_falco_events||0} matching events for this incident rule</span></div><div class="kv"><b>Falco total</b><span>${a.falco_total_24h||0} total events across Kingdom (24h)</span></div><div class="kv"><b>Trivy</b><span>${esc(scan)}</span></div><div class="kv"><b>ClamAV</b><span>${a.source_counts?.clamav?'Evidence present':'No correlated evidence'}</span></div><div class="kv"><b>CrowdSec</b><span>${a.source_counts?.crowdsec?'Evidence present':'No correlated evidence'}</span></div></section><section><h3>ADAPTIVE BASELINE</h3><div class="kv"><b>State</b><span class="${a.baseline?.status==='stable'?'good':a.baseline?.status==='novel'?'warn':''}">${esc((a.baseline?.status||'unknown').toUpperCase())}</span></div><div class="kv"><b>Observed</b><span>${a.baseline?.count||0} matching events across ${a.baseline?.span_hours||0}h</span></div><div class="kv"><b>Baseline confidence</b><span>${a.baseline?.confidence||0}%</span></div><div class="tiny">Kingdom can attenuate Falco-only risk for stable behavior when Trivy is clean. The event is still recorded and the rule is never auto-suppressed.</div></section><section><h3>TOP FALCO RULES</h3>${rules}</section><section><h3>RESPONSE</h3><div class="toolbar"><button class="btn-secondary" onclick="evidence(${id})">Capture Evidence</button>${n?`<button class="btn-primary" onclick="scanIncident(${id},'${esc(n)}')">Scan Now</button>`:''}${top&&n?(expected?`<span class="tag good">✓ EXPECTED${a.expected_rule?.expires_ts?' · expires '+new Date(a.expected_rule.expires_ts*1000).toLocaleString():' · permanent'}</span>`:`<button onclick="markIncidentExpected(${id},'${esc(top)}','${esc(n)}')">Mark Expected</button>`):''}${n?`<button class="danger" onclick="isolateIncident(${id})">Isolate</button>`:''}${allow?`<button class="danger" onclick="createRecovery('${esc(n)}',${id})">Approved Recovery</button>`:''}<button class="btn-success" onclick="resolveIncident(${id})">Resolve</button></div>${!allow&&n?`<div style="margin-top:8px"><b class="tiny">Recovery unavailable:</b>${recovery}</div>`:''}</section>`;document.getElementById('drawer').classList.remove('hidden')}catch(e){toast(e.message,'error')}}async function evidence(id){return guarded('evidence:'+id,'Capturing',async()=>{try{let d=await api(`/api/incidents/${id}/capture-evidence`,{method:'POST',timeout:780000});toast('Evidence captured: '+(d.captured||[]).join(', '));await load();await openIncident(id);return d}catch(e){toast(e.message,'error');throw e}})}async function resolveIncident(id){let r=await kmDialog({title:`Resolve incident #${id}`,text:'Add an operator resolution note. The incident remains available in history.',input:true,value:'Resolved by operator',ok:'Resolve'});if(r===null)return;return guarded('resolve:'+id,'Resolving',async()=>{try{await api(`/api/incidents/${id}/resolve`,{method:'POST',body:JSON.stringify({resolution:r})});toast(`Incident #${id} resolved`);closeDrawer();await load()}catch(e){toast(e.message,'error');throw e}})}async function sendReport(k){try{let d=await api(`/api/reports/send/${k}`,{method:'POST'});toast(`${k} report processed · Discord: ${d.delivery.discord} · n8n: ${d.delivery.n8n}`);load()}catch(e){toast(e.message,'error')}}async function openIncidentHistory(){let rows=await api('/api/incidents?status=all');document.getElementById('drawerTitle').textContent='Incident History';document.getElementById('drawerSubtitle').textContent='Open, investigating, resolved and dismissed Kingdom incidents';document.getElementById('drawerBody').innerHTML=`<section><input id="historySearch" placeholder="Search incidents" oninput="filterIncidentHistory()"></section><section id="incidentHistoryRows">${rows.map(i=>`<div class="event incident-history-row" data-search="${esc((i.container_name||'host')+' '+i.title+' '+i.severity+' '+i.status)}"><div><strong>#${i.id} ${esc(i.container_name||'host')} · ${esc(i.severity).toUpperCase()}</strong><span class="tiny">${esc(i.status)} · ${esc(i.title)}</span></div><button onclick="openIncident(${i.id})">Open</button></div>`).join('')||'<div class="tiny">No incident history.</div>'}</section>`;document.getElementById('drawer').classList.remove('hidden')}function filterIncidentHistory(){let q=document.getElementById('historySearch').value.toLowerCase();document.querySelectorAll('.incident-history-row').forEach(x=>x.classList.toggle('hidden',!x.dataset.search.toLowerCase().includes(q)))}async function openConfidence(){let [ins,ss]=await Promise.all([api('/api/integrations'),api('/api/security/score')]);let names=['falco','trivy','clamav','crowdsec'];document.getElementById('drawerTitle').textContent='Monitoring Confidence';document.getElementById('drawerSubtitle').textContent=`${ss.monitoring_confidence}% visibility across core Kingdom security sensors`;document.getElementById('drawerBody').innerHTML=`<section>${names.map(n=>`<div class="event"><div><strong>${n.toUpperCase()}</strong><span class="tiny">${ins[n]?.configured===false?'Not configured':'Configured'} · ${esc(ins[n]?.status||'unknown')}</span></div><span class="tag ${ins[n]?.status==='ok'?'good':'bad'}">${ins[n]?.status==='ok'?'CONTRIBUTING':'DEGRADED'}</span></div>`).join('')}</section>${(ss.unavailable_sensors||[]).length?`<section><b>Score confidence deductions</b><div class="tiny">Unavailable: ${esc(ss.unavailable_sensors.join(', '))}</div></section>`:'<section><div class="attention-ok">✓ All four core security sensors are contributing.</div></section>'}`;document.getElementById('drawer').classList.remove('hidden')}async function setActivityFilter(category,btn){ACTIVITY_FILTER=category;document.querySelectorAll('#activityFilters button').forEach(x=>x.classList.remove('active'));btn.classList.add('active');await loadActivity()}async function loadActivity(){let ev=await api(`/api/activity?limit=60&include_idle=false${ACTIVITY_FILTER?'&category='+encodeURIComponent(ACTIVITY_FILTER):''}`);document.getElementById('activity').innerHTML=ev.map(e=>`<div class="event"><div><strong>${esc(e.icon)} ${esc(e.subject||e.kind)}</strong><span class="tiny">${esc(e.summary)}</span></div><span class="tiny">${new Date(e.ts*1000).toLocaleTimeString()}</span></div>`).join('')||'<div class="tiny">No activity in this filter.</div>'}async function openBaselines(container=''){let rows=await api('/api/intelligence/baselines?days=7');if(container)rows=rows.filter(x=>x.container===container);document.getElementById('drawerTitle').textContent='Kingdom Baseline Learning';document.getElementById('drawerSubtitle').textContent='Suggestions only — Kingdom never auto-suppresses learned behavior';document.getElementById('drawerBody').innerHTML=`<section>${rows.map(x=>`<div class="baseline-item"><div><div class="baseline-title">${esc(x.container)} · ${esc(x.rule)}</div><div class="baseline-meta">${x.count} events · ${x.days_seen} day(s) observed · ${x.span_hours}h span · baseline ${esc(x.status||'unknown')} · confidence ${x.confidence??x.baseline_confidence}% · effective adjustment ${x.effective_score_adjustment||0}</div><div class="baseline-actions">${x.approved?`<span class="status-chip good">✓ APPROVED${x.suppression?.expires_ts?' · expires '+new Date(x.suppression.expires_ts*1000).toLocaleString():' · permanent'}</span>`:`<button class="btn-primary btn-compact" onclick="suppressFalco('${esc(x.container)}','${esc(x.rule)}')">Review</button><button class="btn-secondary btn-compact" onclick="suppressFalco('${esc(x.container)}','${esc(x.rule)}')">Mark Expected</button>`}</div></div><div class="baseline-side"><span class="status-chip ${x.approved||x.suggested?'good':'warn'}">${x.approved?'EXPECTED':x.suggested?'SUGGESTED':'OBSERVE'}</span></div></div>`).join('')||'<div class="tiny">No recurring behavior has enough history for a baseline suggestion yet.</div>'}</section>`;document.getElementById('drawer').classList.remove('hidden')}
async function recommendationAction(r){if(r.action==='scan'&&r.container){await scan(r.container);return}if(r.action==='incident'&&r.incident_id){await openIncident(r.incident_id);return}if(r.action==='review-falco'&&r.container){await openBaselines(r.container);return}if(r.action==='diagnose'){await openConfidence();return}toast('Open the container security profile for details','warn')}
function closeDrawer(){document.getElementById('drawer').classList.add('hidden')}async function suppressFalco(n,rule){let p=await api('/api/suppressions/preview',{method:'POST',body:JSON.stringify({source:'falco',container_name:n,rule_contains:rule})});let go=await kmDialog({title:'Known-good suppression preview',text:`${p.scope}\n${p.matching_events_24h} matching events in 24h.\nGlobal suppression is blocked.`,ok:'Continue'});if(!go)return;let expiry=await kmDialog({title:'Duration',text:'Hours: 24=1 day, 168=7 days, 0=permanent',input:true,value:'168',ok:'Continue'});if(expiry===null)return;let reason=await kmDialog({title:'Reason',text:p.scope,input:true,value:'Known-good behavior for this container',ok:'Save suppression'});if(!reason)return;await api('/api/suppressions',{method:'POST',body:JSON.stringify({source:'falco',container_name:n,rule_contains:rule,reason,expires_hours:Number(expiry)||0})});toast('Scoped suppression added for '+rule);openDrawer(n)}async function maintenance(n,on){await api(`/api/maintenance/${encodeURIComponent(n)}`,{method:'PUT',body:JSON.stringify({enabled:on,minutes:60,reason:'Operator maintenance'})});openDrawer(n);load()}
async function openDrawer(n){let d=await api(`/api/containers/${encodeURIComponent(n)}/security-profile`);document.getElementById('drawerTitle').textContent=n;document.getElementById('drawerSubtitle').textContent=(d.image||'')+' · '+(d.risk?.state||'unknown');let p=d.policy||{},r=d.risk||{},sc=d.last_successful_scan,attempt=d.latest_scan_attempt,m=d.maintenance||{};let sec=(d.recent_security_events||[]).slice(0,8).map(e=>`<div class="event"><div><strong class="${e.severity==='critical'?'bad':e.severity==='high'?'warn':''}">${esc(e.source)} · ${esc(e.severity)}</strong><span class="tiny">${esc(e.rule||e.message).slice(0,130)}</span>${e.source==='falco'&&e.rule?(e.expected?`<div class="event-actions"><span class="tag good">✓ EXPECTED${e.suppression?.expires_ts?' · '+age(Math.max(0,e.suppression.expires_ts-Math.floor(Date.now()/1000)))+' remaining':' · permanent'}</span></div>`:`<div class="event-actions"><button onclick="suppressFalco('${esc(n)}','${esc(e.rule)}')">Mark Expected</button></div>`):''}</div><span class="tiny">${new Date(e.ts*1000).toLocaleTimeString()}</span></div>`).join('')||'<div class="tiny">No recent security events.</div>';document.getElementById('drawerBody').innerHTML=`<section><div class="kv"><b>Security score</b><span>${r.score??100}/100 · ${esc(r.state||'healthy')}</span></div><div class="kv"><b>Profile</b><span>${esc(d.risk_profile?.profile)} ×${d.risk_profile?.weight}</span></div><div class="kv"><b>Networks</b><span>${esc((d.networks||[]).join(', '))}</span></div><div class="kv"><b>Top factors</b><span>${esc((r.factors||[]).join(' · '))}</span></div></section><section><h3>Recovery & Response Policy</h3><div class="policybar">${policyButton(n,'Approved Rebuild','allow_rebuild',!!p.allow_rebuild)}${policyButton(n,'Auto-Isolate','auto_isolate',!!p.auto_isolate)}${policyButton(n,'Auto-Restart','auto_restart',!!p.auto_restart)}${policyButton(n,'Protected','protected',!!p.protected,'protected')}</div><div class="toolbar" style="margin-top:10px"><button onclick="scan('${esc(n)}')">Scan Now</button><button onclick="act('${esc(n)}','restart')">Restart</button><button class="danger" onclick="act('${esc(n)}','isolate')">Isolate</button><button onclick="maintenance('${esc(n)}',${m.enabled?'false':'true'})">${m.enabled?'End Maintenance':'Maintenance 1h'}</button>${p.allow_rebuild&&!p.protected?`<button class="danger" onclick="createRecovery('${esc(n)}',${(d.incidents||[]).find(x=>!['resolved','dismissed'].includes(x.status))?.id||'null'})">Recovery Plan</button>`:''}</div></section><section><h3>Trivy Verification</h3>${attempt&&attempt.status!=='ok'?`<div class="kv"><b>Latest attempt</b><span class="bad">SCAN ERROR · ${age(Math.max(0,Math.floor(Date.now()/1000)-attempt.ts))}</span></div><div class="tiny bad">${esc(attempt.error||'Trivy scan failed').slice(0,220)}</div>`:(attempt?`<div class="kv"><b>Latest attempt</b><span class="good">OK · ${age(Math.max(0,Math.floor(Date.now()/1000)-attempt.ts))}</span></div>`:'')} ${sc?`<div class="kv"><b>Last successful scan</b><span>${sc.critical} critical · ${sc.high} high · ${sc.medium} medium · ${age(Math.max(0,Math.floor(Date.now()/1000)-sc.ts))}</span></div>`:'<div class="tiny">No successful scan yet.</div>'}</section><section><h3>Recent Security Evidence</h3>${sec}</section><section><h3>Mounts</h3><div class="tiny">${esc((d.mounts||[]).map(x=>`${x.destination} (${x.type}${x.rw?', rw':', ro'})`).join(' · ')||'None')}</div></section>`;document.getElementById('drawer').classList.remove('hidden')}
async function openTrustDiagnostics(){try{let d=await api('/api/suppressions/diagnostics');document.getElementById('drawerTitle').textContent='Trust Pipeline Diagnostics';document.getElementById('drawerSubtitle').textContent=`${d.active} active approval(s) · ${d.matching_events_24h} matched event(s) in 24h · ${d.points_removed} max points removed`;document.getElementById('drawerBody').innerHTML=`<section><div class="tiny">Every approval below is exact container + source + rule scope. This view shows whether the approval actually reaches stored evidence and correlation scoring.</div></section><section>${(d.rows||[]).map(x=>`<div class="event"><div><strong>${esc(x.container_name||'host')} · ${esc(x.rule_contains||x.source)}</strong><span class="tiny">${x.active?'ACTIVE':'INACTIVE'} · ${x.matching_events_24h} matching events · ${x.matching_correlations_24h} matching evaluations · ${x.live_original_risk??0} raw → ${x.live_effective_risk??0} effective · ${x.points_removed} points removed${x.expires_ts?' · expires '+new Date(x.expires_ts*1000).toLocaleString():' · permanent'}</span>${x.sample_match?`<div class="tiny good">Matched: ${esc(x.sample_match).slice(0,180)}</div>`:''}${x.blocker?`<div class="tiny warn">Why not applied: ${esc(x.blocker)}</div>`:''}</div><span class="tag ${x.active&&x.matching_correlations_24h?'good':'warn'}">${x.active&&x.matching_correlations_24h?'APPLIED':x.active?'CHECK':'EXPIRED'}</span></div>`).join('')||'<div class="tiny">No suppression approvals exist.</div>'}</section>`;document.getElementById('drawer').classList.remove('hidden')}catch(e){toast(e.message,'error')}}

function drawHistory(rows){let svg=document.getElementById('historyChart');if(!rows.length){svg.innerHTML='<text x="10" y="55" fill="#8fa3b5">History begins after this upgrade.</text>';document.getElementById('historyMeta').textContent='';return}let w=500,h=110,min=Math.min(...rows.map(x=>x.score)),max=Math.max(...rows.map(x=>x.score));let pts=rows.map((x,i)=>`${(i/(Math.max(1,rows.length-1))*w).toFixed(1)},${(h-10-(x.score/100)*(h-20)).toFixed(1)}`).join(' ');svg.innerHTML=`<polyline fill="none" stroke="#32b7ff" stroke-width="3" points="${pts}"/><line x1="0" y1="${h-10-0.75*(h-20)}" x2="500" y2="${h-10-0.75*(h-20)}" stroke="#294153" stroke-dasharray="4 4"/>`;document.getElementById('historyMeta').textContent=`${rows[0].score} → ${rows[rows.length-1].score} · range ${min}–${max}`}
async function checkUpdate(n){try{toast('Capturing rollback snapshot and checking image…','warn');let p=await api(`/api/updates/${encodeURIComponent(n)}/check`,{method:'POST'});if(p.status==='current'){toast(`${n} is current. Rollback snapshot saved.`,'ok');return}let v=await api(`/api/updates/${p.plan_id}/verify`,{method:'POST'});if(!v.ok){toast(`Update blocked by verification for ${n}`,'error');return}let ok=await kmDialog({title:`Apply verified update to ${n}?`,text:`Rollback snapshot #${p.rollback_snapshot.snapshot_id} is ready. If post-update health fails, Kingdom will automatically restore image ${String(p.old_image_id).slice(0,28)}…`,ok:'Apply Update',danger:true});if(!ok)return;let r=await api(`/api/updates/${p.plan_id}/apply`,{method:'POST'});toast(r.ok?'Update completed; rollback remains available.':'Update failed','ok');load()}catch(e){toast(e.message,'error')}}
async function rollbackUpdate(id,n){if(!(await kmDialog({title:`Rollback ${n}?`,text:'Kingdom will recreate the container from its saved pre-update Docker configuration and immutable previous image ID.',ok:'Rollback',danger:true})))return;try{let r=await api(`/api/updates/${id}/rollback`,{method:'POST'});toast(`Rollback completed for ${n}`,'ok');openUpdates();load()}catch(e){toast(e.message,'error')}}
async function openUpdates(){try{let rows=await api('/api/updates');document.getElementById('drawerTitle').textContent='Update & Rollback Center';document.getElementById('drawerSubtitle').textContent='Staged image verification · immutable rollback snapshots · audit trail';document.getElementById('drawerBody').innerHTML=`<section><h3>SAFE UPDATE MODEL</h3><p class="muted">Kingdom captures the exact running image ID, environment, labels, mounts, restart policy, ports and networks before pulling a candidate. Verified updates can be rolled back to that immutable image/configuration.</p></section><section><h3>RECENT UPDATE PLANS</h3>${rows.map(x=>`<div class="event"><div><strong>${esc(x.container_name)}</strong><span class="tiny">#${x.id} · ${esc(x.status)} · ${new Date(x.created_ts*1000).toLocaleString()}<br>${esc(String(x.old_image_id||'').slice(0,22))} → ${esc(String(x.candidate_image_id||'').slice(0,22))}</span></div><div class="toolbar">${['completed','failed','rolled-back'].includes(x.status)?`<button onclick="rollbackUpdate(${x.id},'${esc(x.container_name)}')">Rollback</button>`:''}</div></div>`).join('')||'<div class="tiny">No update checks yet.</div>'}</section>`;document.getElementById('drawer').classList.remove('hidden')}catch(e){toast(e.message,'error')}}
async function testDiscord(){try{let r=await api('/api/discord/test',{method:'POST'});toast('Discord test sent · '+r.discord,'ok')}catch(e){toast(e.message,'error')}}
async function openRecoveryCenter(){try{let rows=await api('/api/disaster-recovery');document.getElementById('drawerTitle').textContent='Disaster Recovery Center';document.getElementById('drawerSubtitle').textContent='Immutable image/config snapshots · dry-run validation · data-backup awareness';document.getElementById('drawerBody').innerHTML=`<section><div class="tiny">Image/config rollback can restore Docker state. Stateful application data requires a separate verified backup.</div></section><section>${rows.slice(0,80).map(x=>`<div class="event"><div><strong>${esc(x.container_name)} · snapshot #${x.id}</strong><span class="tiny">${new Date(x.ts*1000).toLocaleString()} · ${esc(x.reason)}<br>image ${esc(String(x.image_id||'').slice(0,24))} · ${x.image_present?'image ready':'image missing'} · ${x.data_backup_verified?'data backup verified':'data backup unverified'}${x.compose_source?' · compose '+esc(x.compose_source):''}</span></div><button onclick="testRecovery(${x.id})">Test</button></div>`).join('')||'<div class="tiny">No rollback snapshots yet.</div>'}</section>`;document.getElementById('drawer').classList.remove('hidden')}catch(e){toast(e.message,'error')}}
async function testRecovery(id){try{let r=await api(`/api/disaster-recovery/${id}/test`,{method:'POST'});toast(r.ok?'Rollback dry-run passed':'Rollback dry-run has warnings',r.ok?'ok':'warn');openRecoveryCenter()}catch(e){toast(e.message,'error')}}
async function openDrift(){try{let rows=await api('/api/drift');document.getElementById('drawerTitle').textContent='Configuration Drift';document.getElementById('drawerSubtitle').textContent='Detects unexpected privilege, port, network, mount, capability and configuration changes';document.getElementById('drawerBody').innerHTML=`<section>${rows.map(x=>`<div class="event"><div><strong>${esc(x.container)}</strong><span class="tiny">${esc(x.status)}${(x.changes||[]).length?' · changed: '+esc(x.changes.join(', ')):''}${(x.dangerous||[]).length?'<br><span class="bad">'+esc(x.dangerous.join(' · '))+'</span>':''}${(x.secret_env_keys||[]).length?'<br>secret-like environment keys: '+esc(x.secret_env_keys.join(', ')):''}</span></div><div class="toolbar">${x.status==='unbaselined'?`<button onclick="approveDrift('${esc(x.container)}')">Approve Baseline</button>`:''}${x.status==='drift'?`<button onclick="approveDrift('${esc(x.container)}')">Accept Current</button>`:''}</div></div>`).join('')}</section>`;document.getElementById('drawer').classList.remove('hidden')}catch(e){toast(e.message,'error')}}
async function approveDrift(n){if(!(await kmDialog({title:`Approve configuration baseline for ${n}?`,text:'Future changes to privilege, ports, mounts, capabilities, networks and other configuration will be compared against this snapshot.',ok:'Approve'})))return;await api(`/api/drift/${encodeURIComponent(n)}/approve`,{method:'POST'});toast('Configuration baseline approved for '+n,'ok');openDrift()}
async function openDependencies(){try{let d=await api('/api/dependencies');document.getElementById('drawerTitle').textContent='Kingdom Dependency Map';document.getElementById('drawerSubtitle').textContent=`${d.nodes.length} containers · ${d.edges.length} discovered relationships`;document.getElementById('drawerBody').innerHTML=`<section><h3>SHARED NETWORKS</h3>${Object.entries(d.networks||{}).map(([k,v])=>`<div class="kv"><b>${esc(k)}</b><span>${esc(v.join(', '))}</span></div>`).join('')}</section><section><h3>SHARED VOLUMES</h3>${Object.entries(d.shared_volumes||{}).map(([k,v])=>`<div class="kv"><b>${esc(k).slice(0,45)}</b><span>${esc(v.join(', '))}</span></div>`).join('')||'<div class="tiny">No shared volumes detected.</div>'}</section>`;document.getElementById('drawer').classList.remove('hidden')}catch(e){toast(e.message,'error')}}
async function openValidation(){try{let r=await api('/api/system/validate');document.getElementById('drawerTitle').textContent='System Validation';document.getElementById('drawerSubtitle').textContent=`${r.passed}/${r.total} checks passed · ${r.ok?'production-ready checks passed':'review failures'}`;document.getElementById('drawerBody').innerHTML=`<section>${r.checks.map(x=>`<div class="event"><div><strong>${esc(x.check)}</strong><span class="tiny">${esc(String(x.detail||''))}</span></div><span class="tag ${x.ok?'good':'bad'}">${x.ok?'PASS':'FAIL'}</span></div>`).join('')}</section><section><div class="toolbar"><button onclick="simulateScenario('falco-only')">Simulate Falco</button><button onclick="simulateScenario('multi-source')">Simulate Multi-source</button><button onclick="simulateScenario('update-failure')">Simulate Rollback</button></div></section>`;document.getElementById('drawer').classList.remove('hidden')}catch(e){toast(e.message,'error')}}
async function simulateScenario(s){try{let r=await api(`/api/simulate/${s}`,{method:'POST'});await kmDialog({title:'Simulation: '+s,text:JSON.stringify(r.result,null,2),ok:'Close'})}catch(e){toast(e.message,'error')}}
async function load(){let [ins,fs,ts,ss,incs]=await Promise.all([api('/api/integrations'),api('/api/security/falco/summary'),api('/api/security/trivy/summary'),api('/api/security/score'),api('/api/incidents')]);let optional=await Promise.allSettled([api('/api/containers'),api('/api/security/explain-score'),api('/api/security/history?hours=168'),api('/api/recommendations'),api('/api/reports/history')]);let val=(i,f)=>optional[i].status==='fulfilled'?optional[i].value:f,cs=val(0,[]),explain=val(1,{contributors:[]}),hist=val(2,[]),recs=val(3,[]),reph=val(4,[]);if(optional.some(x=>x.status==='rejected'))toast('Some secondary dashboard data is delayed; core security state is still available.','warn');let engineHealth=ss.sensor_health||ins;let healthy=['clamav','crowdsec','falco','trivy'].every(k=>engineHealth[k]?.status==='ok');document.getElementById('systemState').textContent=healthy?'All Systems Operational':'Review Security Engines';document.getElementById('systemState').className=healthy?'good':'warn';document.getElementById('lastCheck').textContent='Last check: just now';let color=ss.score>=90?'#4ee07d':ss.score>=75?'#92e65c':ss.score>=55?'#ffd24d':ss.score>=35?'#ff9f35':'#ff5f57',ring=document.getElementById('scoreRing');ring.style.setProperty('--score',ss.score);ring.style.setProperty('--mood',color);document.getElementById('score').textContent=ss.score;document.getElementById('scoreStatus').textContent=ss.status;document.getElementById('scoreStatus').style.color=color;document.getElementById('overallRisk').textContent=ss.overall_risk;document.getElementById('confidence').textContent=ss.monitoring_confidence;let dm=ss.dimensions||{};document.getElementById('dimensions').textContent=`Threat ${dm.threat??'—'} · Vulnerability ${dm.vulnerability??'—'} · Exposure ${dm.exposure??'—'} · Monitoring ${dm.monitoring??'—'} · Trust ${dm.trust??'—'}`;document.getElementById('scoreText').textContent=(ss.unavailable_sensors||[]).length?`Monitoring degraded: ${(ss.unavailable_sensors||[]).join(', ')} unavailable.`:ss.score>=90?'Your Kingdom is secure. No significant correlated threats are active.':ss.score>=75?'Your Kingdom is stable. A few signals deserve observation.':ss.score>=55?'Elevated activity detected. Review the risk leaderboard.':ss.score>=35?'High-risk evidence needs investigation.':'Critical correlated risk requires immediate attention.';document.getElementById('suppressed').textContent=ss.suppressed_24h||0;document.getElementById('moodFace').className='face '+ss.mood;let halo=document.querySelector('.facehalo');halo.style.borderColor=color;halo.style.boxShadow=`0 0 0 9px ${color}12,0 0 42px ${color}35`;let sc=ss.severity_counts||{};['Critical','High','Medium','Low'].forEach(k=>document.getElementById('sev'+k).textContent=sc[k.toLowerCase()]||0);let urgent=ss.immediate_attention||[],medium=(incs||[]).filter(x=>x.severity==='medium').length;document.getElementById('attention').innerHTML='<h3>IMMEDIATE ATTENTION</h3>'+(urgent.length?urgent.map(x=>`<div class="event"><div><strong class="bad">${esc(x.container)} · ${esc(x.state)}</strong><span class="tiny">${esc(x.factors[0])}</span></div><b>${x.score}</b></div>`).join(''):`<div class="attention-ok"><div class="check">✓</div>No urgent incidents.${medium?`<div class="warn">${medium} medium incident${medium>1?'s':''} require review.</div>`:''}</div>`);let fc=fs.counts_24h||{},sched=(ts.scheduler||{}).state||(ts.auto_scan_enabled?'starting':'disabled'),trivystatus=sched==='error'?'error':sched.startsWith('scanning:')?'scanning':engineHealth.trivy?.status||ins.trivy.status;document.getElementById('engines').innerHTML=engineCard('Falco','🦅',engineHealth.falco?.status||ins.falco.status,`<div class="engine-kpi">${fs.events_24h||0}</div><div class="tiny">Events (24h) · <span class="sev-critical">${fc.critical||0} critical</span> · <span class="sev-high">${fc.high||0} high</span><br>Last event ${age(fs.last_event_age_seconds)}</div>`)+engineCard('Trivy','◇',trivystatus,`<div class="engine-kpi">${ts.scans_24h||0}</div><div class="tiny">Scans (24h) · <span class="sev-critical">${ts.critical_24h||0} critical</span> · <span class="sev-high">${ts.high_24h||0} high</span><br>Scheduler: ${esc(sched)}${(ts.scheduler||{}).last_error?'<br><span class="bad">'+esc((ts.scheduler||{}).last_error).slice(0,100)+'</span>':''}</div>`)+engineCard('ClamAV','⬡',engineHealth.clamav?.status||ins.clamav.status,`<div class="engine-kpi">${(engineHealth.clamav?.status||ins.clamav.status)==='ok'?'Clean':'Review'}</div><div class="tiny">Malware scanning sensor</div>`)+engineCard('CrowdSec','♜',engineHealth.crowdsec?.status||ins.crowdsec.status,`<div class="engine-kpi">${(engineHealth.crowdsec?.status||ins.crowdsec.status)==='ok'?'Active':'Review'}</div><div class="tiny">Host intrusion decisions & firewall context</div>`);document.getElementById('incidents').innerHTML=incs.length?incs.slice(0,8).map(i=>`<div class="incident-item"><div class="incident-main"><div class="incident-title"><strong class="${i.severity==='critical'?'bad':i.severity==='high'?'warn':''}">#${i.id} ${esc(i.container_name||'host')} · ${esc(i.severity).toUpperCase()}</strong></div><div class="incident-meta">${esc(i.title)} · ${esc((i.sources||[]).join(', '))}</div><div class="event-actions"><button class="btn-primary" onclick="openIncident(${i.id})">⌕ Investigate</button><button class="btn-secondary" onclick="evidence(${i.id})">▣ Capture Evidence</button><button class="btn-success" onclick="resolveIncident(${i.id})">✓ Resolve</button></div></div><span class="status-chip ${i.status==='open'?'warn':i.status==='investigating'?'warn':'good'} incident-state">${esc(i.status)}</span></div>`).join(''):'<div class="attention-ok">✓ No active incidents.</div>';document.getElementById('scoreExplain').innerHTML=(explain.contributors||[]).length?(explain.contributors||[]).slice(0,8).map(x=>`<div class="event"><div><strong>${esc(x.subject)}</strong><span class="tiny">${esc(x.detail)}</span></div><b>−${x.points_lost}</b></div>`).join(''):'<div class="attention-ok">✓ No active deductions.</div>';document.getElementById('leaderboard').innerHTML=(ss.leaderboard||[]).map(x=>`<tr class="clickable" onclick="openDrawer('${esc(x.container)}')"><td><b>${esc(x.container)}</b></td><td><b>${x.score}</b></td><td class="state ${x.score>=75?'good':x.score>=55?'warn':'bad'}">${esc(x.state).toUpperCase()}</td><td>${esc(x.profile)}</td><td class="tiny">${esc(x.factors[0])}</td></tr>`).join('');await loadActivity();drawHistory(hist);RECS=recs;document.getElementById('recommendations').innerHTML=recs.length?recs.slice(0,10).map((r,idx)=>`<div class="event recommend ${esc(r.priority)}"><div><strong>${esc(r.title)}</strong><span class="tiny">${esc(r.detail)}</div><div class="baseline-actions"><button class="btn-secondary btn-compact" onclick='recommendationAction(RECS[${idx}])'>${r.action==='scan'?'Scan Now':r.action==='incident'?'Investigate':r.action==='diagnose'?'Diagnose':r.action==='review-falco'?'Review Falco':'Review'}</button></div></div><span class="tag ${r.priority==='critical'||r.priority==='high'?'bad':r.priority==='medium'?'warn':'good'}">${esc(r.priority)}</span></div>`).join(''):'<div class="attention-ok">✓ No recommendations right now.</div>';document.getElementById('reporting').innerHTML=`<div class="kv"><b>Discord</b><span class="${ins.discord?.configured?'good':'muted'}">${ins.discord?.configured?'Configured':'Not configured'}</span></div><div class="kv"><b>n8n</b><span class="${ins.n8n?.configured?'good':'muted'}">${ins.n8n?.configured?'Configured':'Not configured'}</span></div><div class="kv"><b>Recent reports</b><span>${reph.length}</span></div>`;document.getElementById('containers').innerHTML=cs.map(c=>{let p=c.policy||{};return `<div class="container-row" onclick="openDrawer('${esc(c.name)}')"><div style="min-width:0"><b>${esc(c.name)}</b> <span class="tag ${c.state==='running'?'good':'bad'}">${esc(c.state)}</span><div class="tiny">${esc(c.image)} · ${esc(c.status)}</div><div class="policybar">${policyButton(c.name,'Approved Rebuild','allow_rebuild',!!p.allow_rebuild)}${policyButton(c.name,'Auto-Isolate','auto_isolate',!!p.auto_isolate)}${policyButton(c.name,'Auto-Restart','auto_restart',!!p.auto_restart)}${policyButton(c.name,'Auto-Update','auto_update',!!p.auto_update)}${policyButton(c.name,'Protected','protected',!!p.protected,'protected')}</div></div><div class="toolbar"><button class="btn-secondary btn-compact" onclick="event.stopPropagation();act('${esc(c.name)}','start')">Start</button><button class="btn-secondary btn-compact" onclick="event.stopPropagation();act('${esc(c.name)}','restart')">Restart</button><button class="danger btn-compact" onclick="event.stopPropagation();act('${esc(c.name)}','stop')">Stop</button><button class="btn-secondary btn-compact" onclick="event.stopPropagation();scan('${esc(c.name)}')">Trivy</button><button class="btn-secondary btn-compact" onclick="event.stopPropagation();checkUpdate('${esc(c.name)}')">Update</button></div></div>`}).join('');document.getElementById('footerEval').textContent='Last full evaluation '+new Date(ss.evaluated_ts*1000).toLocaleTimeString()}
if(TOKEN){_api('/api/auth/verify',{timeout:15000}).then(async()=>{document.getElementById('login').classList.add('hidden');try{let boot=await _api('/api/dashboard/bootstrap',{timeout:3000});if(boot?.score)renderWarmScore(boot.score,boot.saved_ts)}catch{}return load()}).catch(()=>{})}setInterval(()=>{if(TOKEN)load().catch(()=>{})},30000)
</script></body></html>'''

